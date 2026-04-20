# Module: Escrow-Bitlocker
# Provides BitLocker activation and Cloud Escrow (Firestore)
# Requirement: Launcher context (AccessToken, ProjectId)

function Write-ModuleLog {
    param([string]$Message, [string]$Level = "INFO")
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Stamp] [$Level] [Mod:BitLocker] $Message"
    Add-Content -Path "C:\ProgramData\Rekordata\Logs\Governance.log" -Value $Line
    Write-Host $Line
}

function Get-EncryptionStatus {
    $drive = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq "C:" }
    if ($null -eq $drive) { return "None" }
    
    $statusMap = @{
        0 = "FullyDecrypted"
        1 = "FullyEncrypted"
        2 = "EncryptionInProgress"
        3 = "DecryptionInProgress"
        4 = "EncryptionPaused"
        5 = "DecryptionPaused"
    }
    return $statusMap[[int]$drive.ProtectionStatus]
}

function Get-BitLockerKey {
    $drive = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq "C:" }
    if ($null -eq $drive) { return $null }
    
    $keyProt = @()
    $drive.GetKeyProtectors(3, [ref]$keyProt) | Out-Null # 3 = NumericalPassword
    
    if ($keyProt.Length -gt 0) {
        $keyId = $keyProt[0]
        $pass = ""
        $drive.GetKeyProtectorNumericalPassword($keyId, [ref]$pass) | Out-Null
        return @{
            ID       = $keyId
            Password = $pass
        }
    }
    return $null
}

function Invoke-BitLockerActivation {
    param([string]$Method = "xts_aes256")
    Write-ModuleLog "Activating BitLocker (Method: $Method)..."
    
    # Try to enable protection with TPM. Capture output for debug.
    $output = manage-bde -on C: -Used -EncryptionMethod $Method -SkipHardwareTest -RecoveryPassword 2>&1
    $success = $LASTEXITCODE -eq 0
    
    # Force a key backup to AD/Local if possible
    manage-bde -protectors -adbackup C: -id (Get-BitLockerKey).ID | Out-Null
    
    return @{ Success = $success; Output = ($output -join "`n") }
}

function Send-Escrow {
    param([string]$AccessToken, [string]$ProjectId, [string]$KeyId, [string]$Password)
    Write-ModuleLog "Sending Key Escrow to Cloud..."
    
    $Id = $env:COMPUTERNAME
    $Url = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/escrow/$Id"
    
    $Payload = @{
        fields = @{
            key_id     = @{ stringValue = $KeyId }
            recovery   = @{ stringValue = $Password }
            created_at = @{ stringValue = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
        }
    } | ConvertTo-Json -Depth 10
    
    $Headers = @{ Authorization = "Bearer $AccessToken" }
    
    try {
        Invoke-RestMethod -Uri $Url -Method Patch -Headers $Headers -ContentType "application/json" -Body $Payload | Out-Null
        Write-ModuleLog "Escrow Completed Successfully."
    }
    catch {
        Write-ModuleLog "Escrow Failed: $_" "ERROR"
    }
}

# --- Main Execution ---
Write-ModuleLog "Checking BitLocker Governance..."

$status = Get-EncryptionStatus
Write-ModuleLog "Volume C: Status is '$status'."

# If not protected, activate
if ($status -ne "FullyEncrypted" -and $status -ne "EncryptionInProgress") {
    $activation = Invoke-BitLockerActivation
    if (-not $activation.Success) {
        Write-ModuleLog "Activation step failed. Detail: $($activation.Output)" "ERROR"
    }
}

# Always ensure escrow is up to date if we have a key
$key = Get-BitLockerKey
if ($null -ne $key) {
    # In a real environment, we'd check if checksum matches cloud, 
    # for now we send it to ensure safety.
    if ($context.AccessToken -and $context.ProjectId) {
        Send-Escrow -AccessToken $context.AccessToken -ProjectId $context.ProjectId -KeyId $key.ID -Password $key.Password
    }
    else {
        Write-ModuleLog "Skipping cloud escrow: Missing context." "WARNING"
    }
}
else {
    Write-ModuleLog "No BitLocker numerical password found to escrow." "WARNING"
}
