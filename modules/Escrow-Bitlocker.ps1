param(
    [hashtable]$Context
)

# 1. Configurazione Iniziale & Validazione
$LogPath = $Context.LogPath
$AccessToken = $Context.AccessToken
$RegistryPath = $Context.RegistryPath
$BitlockerFolderId = $Context.folderId
$BitlockerUsedSpaceOnly = $true
if ($null -ne $Context.usedSpaceOnly) { $BitlockerUsedSpaceOnly = $Context.usedSpaceOnly }

if (-not $BitlockerFolderId) {
    # Se manca l'ID, non procediamo per sicurezza.
    # Creiamo un log entry e restituiamo errore al Launcher.
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [ERROR] [Mod:BitLocker] CRITICAL: BitlockerFolderId mancante nel manifest. Escrow impossibile."
    if ($LogPath) { Add-Content -Path (Join-Path $LogPath "Governance.log") -Value $logEntry }
    
    return [PSCustomObject]@{
        Module  = "bitlocker-escrow"
        Success = $false
        Status  = "Config Error"
        Details = @{ error = "Mandatory folderId missing in manifest/context" }
    }
}

function Write-ModuleLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Mod:BitLocker] $Message"
    Add-Content -Path (Join-Path $LogPath "Governance.log") -Value $logEntry
    Write-Host $logEntry
}

function Get-RegistryValueSecure {
    param([string]$Path, [string]$Name)
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $subKeyPath = $Path.Replace("HKLM:\", "").Replace("HKEY_LOCAL_MACHINE\", "")
        $subKey = $baseKey.OpenSubKey($subKeyPath)
        if ($subKey) {
            $value = $subKey.GetValue($Name)
            $subKey.Close(); $baseKey.Close()
            return $value
        }
        $baseKey.Close()
        return $null
    } catch { return $null }
}

function Send-DriveUploadMultipart {
    param([string]$FileName, [string]$Content, [string]$FolderId, [string]$AccessToken)
    try {
        $boundary = [System.Guid]::NewGuid().ToString()
        $metadata = @{ name = $FileName; parents = @($FolderId) } | ConvertTo-Json -Compress
        $body = @("--$boundary", "Content-Type: application/json; charset=UTF-8", "", $metadata, "--$boundary", "Content-Type: text/plain; charset=UTF-8", "", $Content, "--${boundary}--") -join "`r`n"
        $uri = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true"
        Invoke-RestMethod -Uri $uri -Method Post -Headers @{ "Authorization" = "Bearer $AccessToken" } -Body $body -ContentType "multipart/related; boundary=$boundary" -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}

function Invoke-PremiumNotification {
    Write-ModuleLog "Triggering User Notification UI..."
    $uiPath = "C:\ProgramData\Rekordata\BitLocker-UI.ps1"
    $uiScript = @"
Add-Type -AssemblyName System.Windows.Forms
`$msg = "REKORDATA - Sicurezza Sistemi`n`nLa protezione BitLocker e' stata attivata con successo sul disco di sistema. I tuoi dati sono ora in fase di protezione.`n`nPer completare ufficialmente la configurazione, e' consigliato un riavvio del computer al termine della sessione attuale.`n`nVuoi riavviare ora?"
`$title = "Protezione Disco Attivata"
`$res = [System.Windows.Forms.MessageBox]::Show(`$msg, `$title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Information)
if (`$res -eq [System.Windows.Forms.DialogResult]::Yes) {
    shutdown.exe /r /t 60 /c "REKORDATA: Riavvio programmato per finalizzare la sicurezza del sistema. Salva il tuo lavoro." /f
}
Unregister-ScheduledTask -TaskName "RekordataBitLockerUI" -Confirm:`$false -ErrorAction SilentlyContinue
Remove-Item -Path `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"@
    $uiScript | Out-File -FilePath $uiPath -Encoding UTF8 -Force
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$uiPath`""
    $principal = New-ScheduledTaskPrincipal -GroupId "Users"
    Register-ScheduledTask -TaskName "RekordataBitLockerUI" -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName "RekordataBitLockerUI"
}

function Get-BitLockerMDMPolicy {
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    if (-not (Test-Path $fvePath)) { return @{ PolicyPresent = $false } }
    $rawMethod = (Get-ItemProperty -Path $fvePath -ErrorAction SilentlyContinue).EncryptionMethodWithXtsOs
    $methodMap = @{ 3 = "aes128"; 4 = "aes256"; 6 = "xts_aes128"; 7 = "xts_aes256" }
    $encryptionMethod = "xts_aes256"
    if($methodMap.ContainsKey([int]$rawMethod)){ $encryptionMethod = $methodMap[[int]$rawMethod] }
    return @{ PolicyPresent = $true; EncryptionMethod = $encryptionMethod }
}

function Invoke-BitLockerActivation {
    param([string]$EncryptionMethod = "xts_aes256")
    try {
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($vol.ProtectionStatus -eq "On") { return @{ Success = $true; StatusNote = "already_active" } }
        
        Write-ModuleLog "Activating BitLocker (Method: $EncryptionMethod)..."
        
        # 1. Add Protectors (TPM + RecoveryPassword)
        $pOutput = & manage-bde -protectors -add $env:SystemDrive -tpm -RecoveryPassword 2>&1
        if ($LASTEXITCODE -ne 0) {
             Write-ModuleLog "Failed to add protectors: $($pOutput -join ' | ')" "ERROR"
             return @{ Success = $false; StatusNote = "protector_failed" }
        }

        # 2. Start Encryption
        $cmdArgs = @("-on", $env:SystemDrive, "-EncryptionMethod", $EncryptionMethod, "-SkipHardwareTest", "-Used")
        $output = & manage-bde.exe @cmdArgs 2>&1
        
        if ($LASTEXITCODE -eq 0 -or $output -match "already encrypted" -or $output -match "encryption is in progress") { 
            Invoke-PremiumNotification
            return @{ Success = $true; StatusNote = "activated" } 
        }
        
        Write-ModuleLog "Activation failed: $($output -join ' | ')" "ERROR"
        return @{ Success = $false; StatusNote = "error" }
    } catch { 
        Write-ModuleLog "Fatal Activation Error: $_" "ERROR"
        return @{ Success = $false; StatusNote = "failed" } 
    }
}
#endregion

#region Execution
Write-ModuleLog "Checking BitLocker Governance..."
$mdmPolicy = Get-BitLockerMDMPolicy
if (-not $mdmPolicy.PolicyPresent) {
    Write-ModuleLog "No MDM Policy for BitLocker. Skipping."
    return
}

$activation = Invoke-BitLockerActivation -EncryptionMethod $mdmPolicy.EncryptionMethod
if ($activation.Success) {
    Write-ModuleLog "BitLocker State OK ($($activation.StatusNote)). Processing Escrow..."
    $blVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $recoveryProtector = $blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    
    if ($recoveryProtector) {
        $id = $recoveryProtector.KeyProtectorId
        $lastSyncId = Get-RegistryValueSecure -Path $RegistryPath -Name "LastBitLockerSyncId"
        if ($id -eq $lastSyncId) {
            Write-ModuleLog "Key already synced."
        } else {
            $serial = (Get-CimInstance Win32_Bios).SerialNumber
            $content = "Hostname: $($env:COMPUTERNAME)`nSerial: $serial`nDisk: C:`nID: $id`nKey: $($recoveryProtector.RecoveryPassword)"
            $fileName = "$($env:COMPUTERNAME)_C_BitLocker.txt"
            
            if (Send-DriveUploadMultipart -FileName $fileName -Content $content -FolderId $BitlockerFolderId -AccessToken $AccessToken) {
                Write-ModuleLog "Escrow successful."
                New-ItemProperty -Path $RegistryPath -Name "LastBitLockerSyncId" -Value $id -PropertyType String -Force | Out-Null
            } else {
                Write-ModuleLog "Escrow failed." "ERROR"
            }
        }
    }
} else {
    Write-ModuleLog "Activation step failed." "ERROR"
}

# Prepare return object
$finalSuccess = [bool]$activation.Success
$finalStatus = "Failed"
if ($finalSuccess) { $finalStatus = "Completed" }

$syncStatus = "none"
if ($id -and $id -eq $lastSyncId) { $syncStatus = "already_synced" }
elseif ($id) { $syncStatus = "uploaded" }

# Return ResultObject to Launcher
return [PSCustomObject]@{
    Module  = "bitlocker-escrow"
    Success = $finalSuccess
    Status  = $finalStatus
    Details = @{
        activationStatus = $activation.StatusNote
        policyPresent    = $mdmPolicy.PolicyPresent
        synced           = $syncStatus
    }
}
#endregion
