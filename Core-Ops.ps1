<#
.SYNOPSIS
    Core Operations Script for Rekordata - Garbage Collector for User Profiles
.DESCRIPTION
    This script is dynamically fetched and executed by the Bootstrap-Agent.ps1.
    It performs garbage collection of user profiles and reports telemetry.
.NOTES
    Author: Rekordata Team
    Version: 1.0.0
#>

#region Configuration Variables
$LogPath = "C:\ProgramData\Rekordata\Logs"
$TelemetryEnabled = $true
$ProfilePath = "C:\Users"
$MinProfileAgeDays = 1  # Profiles older than this are candidates for cleanup
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"
$BitlockerEnabled = $true
$BitlockerUsedSpaceOnly = $true  # $true = Cripta solo spazio usato (veloce) | $false = Full Disk
$BitlockerFolderId = "1sNEWJvrziCfwA-VFSUrSZj-0NaCX7t0A"
#endregion

#region Helper Functions
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
    
    # Write to log file
    $logFile = Join-Path $LogPath "Core-Ops.log"
    Add-Content -Path $logFile -Value $logEntry
    
    # Also write to console for debugging
    Write-Host $logEntry
}

function Get-RegistryValueSecure {
    param([string]$Path, [string]$Name)
    try {
        # Usa .NET per bypassare la redirection del registro
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $subKeyPath = $Path.Replace("HKLM:\", "").Replace("HKEY_LOCAL_MACHINE\", "")
        $subKey = $baseKey.OpenSubKey($subKeyPath)
        
        if ($subKey) {
            $value = $subKey.GetValue($Name)
            $subKey.Close()
            $baseKey.Close()
            return $value
        }
        $baseKey.Close()
        return $null
    }
    catch {
        # Delimitazione sicura per evitare errori di parsing con i due punti
        Write-Log "Failed to access registry path ${Path}. Error: $_" "DEBUG"
        return $null
    }
}

function ConvertFrom-Base64Json {
    param([string]$Base64String)
    try {
        $bytes = [System.Convert]::FromBase64String($Base64String)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return ConvertFrom-Json $json
    }
    catch {
        Write-Log "Failed to convert MDMAuth to JSON: $_" "ERROR"
        return $null
    }
}

function ConvertTo-Base64Url {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $b64 = [Convert]::ToBase64String($bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-GcpAccessToken {
    param([object]$ServiceAccount)
    
    try {
        # 1. Prepare Header and Claim
        $header = @{ alg = "RS256"; typ = "JWT" } | ConvertTo-Json -Compress
        
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $claim = @{
            iss   = $ServiceAccount.client_email
            scope = "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/drive"
            aud   = "https://oauth2.googleapis.com/token"
            exp   = $now + 3600
            iat   = $now
        } | ConvertTo-Json -Compress

        $b64Header = ConvertTo-Base64Url -InputString $header
        $b64Claim = ConvertTo-Base64Url -InputString $claim
        $message = "$b64Header.$b64Claim"

        # 2. Extract and format Private Key
        $privateKeyPem = $ServiceAccount.private_key
        $privateKeyPem = $privateKeyPem.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("`n", "").Replace("`r", "").Trim()
        $keyBytes = [Convert]::FromBase64String($privateKeyPem)

        # 3. Handle RS256 Signature using .NET Framework 4.8 compatible method
        # We need to sign the SHA256 hash of the message
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))

        # Import using CngKey (PowerShell 5.1 friendly)
        $cngKey = [System.Security.Cryptography.CngKey]::Import($keyBytes, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $rsaCng = New-Object System.Security.Cryptography.RSACng($cngKey)
        
        # Sign the hash
        $signatureBytes = $rsaCng.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $b64Signature = [Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        # 4. Build JWT and Request Access Token
        $jwt = "$message.$b64Signature"
        $tokenResponse = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method Post -Body @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion  = $jwt
        }

        # Cleanup
        $rsaCng.Dispose()
        $cngKey.Dispose()

        return $tokenResponse.access_token
    }
    catch {
        Write-Log "Failed to generate GCP Access Token (Compatibility Error): $_" "ERROR"
        return $null
    }
}

function Send-FirestoreTelemetry {
    param(
        [hashtable]$Data,
        [string]$AccessToken,
        [string]$ProjectId
    )
    if (-not $TelemetryEnabled) { return $false }
    
    try {
        # Format for Firestore Document REST API
        $firestoreBody = @{
            fields = @{
                deviceId        = @{ stringValue = $Data.deviceId }
                timestamp       = @{ timestampValue = $Data.timestamp }
                eventType       = @{ stringValue = $Data.eventType }
                profilesFound   = @{ integerValue = $Data.profilesFound }
                profilesCleaned = @{ integerValue = $Data.profilesCleaned }
                bitlockerSync   = @{ stringValue = $Data.bitlockerSync }
            }
        } | ConvertTo-Json -Depth 5

        # Collection 'telemetry', document ID auto-generated
        $uri = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/telemetry"
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }

        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $firestoreBody -TimeoutSec 15
        Write-Log "Telemetry successfully pushed to Firestore Document ID: $($response.name)"
        return $true
    }
    catch {
        Write-Log "Failed to push telemetry to Firestore: $_" "ERROR"
        return $false
    }
}

function Send-DriveUploadMultipart {
    param(
        [string]$FileName,
        [string]$Content,
        [string]$FolderId,
        [string]$AccessToken
    )
    
    try {
        $boundary = [System.Guid]::NewGuid().ToString()
        $metadata = @{ 
            name    = $FileName
            parents = @($FolderId)
        } | ConvertTo-Json -Compress

        # Costruisce il corpo multipart in memoria per evitare file temporanei
        $bodyParts = @(
            "--$boundary",
            "Content-Type: application/json; charset=UTF-8",
            "",
            $metadata,
            "--$boundary",
            "Content-Type: text/plain; charset=UTF-8",
            "",
            $Content,
            "--${boundary}--"
        )
        $body = $bodyParts -join "`r`n"

        $uri = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsAllDrives=true"
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
        }

        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body -ContentType "multipart/related; boundary=$boundary" -ErrorAction Stop
        Write-Log "File successfully uploaded to Drive: $($response.name) (ID: $($response.id))"
        
        # Vaporizzazione immediata del contenuto sensibile dalla memoria
        $Content = $null
        $body = $null
        [System.GC]::Collect()

        return $true
    }
    catch {
        Write-Log "Failed to upload file to Google Drive: $_" "ERROR"
        return $false
    }
}

# WHITELIST: Profili mai toccati dal Garbage Collector.
# Aggiungere qui i pattern dei docenti o degli admin operativi.
$GC_ExcludeList = @("Administrator", "ladmin", "Public", "Default", "Default User", "All Users")
# Pattern aggiuntivi per protezione docenti (es. prefisso "doc." nei profili GCPW)
$GC_ExcludePatterns = @("doc.*", "admin.*", "supervisore.*")

function Get-StaleProfiles {
    <#
    .SYNOPSIS
        Interroga WMI per ottenere profili utente inattivi da eliminare.
        Usa Win32_UserProfile per accedere a LastUseTime e Special in modo nativo.
        NOTA CRITICA: Usa SOLO questa funzione per identificare i candidati, mai
        Get-ChildItem, in modo da operare always via CIM e pulire anche il registro.
    #>
    param([int]$MinAgeDays)
    try {
        $cutoffDate = (Get-Date).AddDays(-$MinAgeDays)

        $candidates = Get-CimInstance -Class Win32_UserProfile | Where-Object {
            $pName = $_.LocalPath.Split('\')[-1]
            
            # Esclude profili di sistema e cartelle speciali Windows
            $_.Special -eq $false -and
            # Esclude la whitelist nominativa
            $pName -notin $GC_ExcludeList -and
            # Esclude pattern docenti/admin via wildcard
            (-not ($GC_ExcludePatterns | Where-Object { $pName -like $_ })) -and
            # Controlla l'ultimo UTILIZZO reale
            $_.LastUseTime -ne $null -and
            $_.LastUseTime -lt $cutoffDate -and
            # Safety: non toccare il profilo utente attualmente loggato
            $_.Loaded -eq $false
        }
        return $candidates
    }
    catch {
        Write-Log "Error querying Win32_UserProfile via CIM: $_" "ERROR"
        return @()
    }
}

function Cleanup-Profile {
    <#
    .SYNOPSIS
        Rimuove il profilo utente usando Remove-CimInstance.
        CRITICO: Remove-CimInstance su Win32_UserProfile rimuove ATOMICAMENTE
        sia la cartella C:\Users\<nome> che la chiave di registro in
        HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList.
        Questo previene il "zombie profile" (badge presente, cartella assente,
        Windows crea profilo temporaneo al login successivo).
    #>
    param([CimInstance]$ProfileInstance)
    try {
        $profileName = $ProfileInstance.LocalPath.Split('\')[-1]
        Write-Log "[GC] Avvio pulizia profilo CIM: $profileName (LastUse: $($ProfileInstance.LastUseTime))"

        # Doppio controllo di sicurezza: non rimuovere se caricato
        if ($ProfileInstance.Loaded) {
            Write-Log "[GC] Profilo $profileName e' attualmente caricato. Skip per sicurezza." "WARN"
            return $false
        }

        Remove-CimInstance -InputObject $ProfileInstance -ErrorAction Stop
        Write-Log "[GC] Profilo $profileName rimosso (filesystem + registro)." 
        return $true
    }
    catch {
        Write-Log "[GC] Errore rimozione profilo CIM $($ProfileInstance.LocalPath): $_" "ERROR"
        return $false
    }
}

function Invoke-PremiumNotification {
    <#
    .SYNOPSIS
        Crea uno script UI e un task programmato per eseguirlo nella sessione utente.
        Permette all'utente di scegliere tra riavvio immediato o posticipato.
    #>
    Write-Log "Generazione UI Premium per l'utente..."
    $uiPath = "C:\ProgramData\Rekordata\BitLocker-UI.ps1"

    $uiScript = @"
Add-Type -AssemblyName System.Windows.Forms
`$msg = "REKORDATA - Sicurezza Sistemi`n`nLa protezione BitLocker e' stata attivata con successo sul disco di sistema. I tuoi dati sono ora in fase di protezione.`n`nPer completare ufficialmente la configurazione, e' consigliato un riavvio del computer al termine della sessione attuale.`n`nVuoi riavviare ora?"
`$title = "Protezione Disco Attivata"

# Messaggio con tasti Sì e No. Sì = Riavvio tra 60s, No = Chiusura semplice.
`$res = [System.Windows.Forms.MessageBox]::Show(`$msg, `$title, [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Information)

if (`$res -eq [System.Windows.Forms.DialogResult]::Yes) {
    shutdown.exe /r /t 60 /c "REKORDATA: Riavvio programmato per finalizzare la sicurezza del sistema. Salva il tuo lavoro." /f
}

# --- SELF CLEANUP (Premium UI) ---
# Rimuove il task e lo script stesso alla chiusura per non lasciare tracce
Unregister-ScheduledTask -TaskName "RekordataBitLockerUI" -Confirm:`$false -ErrorAction SilentlyContinue
Remove-Item -Path `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"@

    try {
        # Hardening Permessi Cartella
        if (-not (Test-Path "C:\ProgramData\Rekordata")) { 
            New-Item -ItemType Directory -Path "C:\ProgramData\Rekordata" -Force | Out-Null 
            # Rimuove ereditarietà e dà accesso solo a SYSTEM e Admins
            $acl = Get-Acl "C:\ProgramData\Rekordata"
            $acl.SetAccessRuleProtection($true, $false)
            $rules = @(
                New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
                New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"),
                New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
            )
            $rules | ForEach-Object { $acl.AddAccessRule($_) }
            Set-Acl "C:\ProgramData\Rekordata" $acl
        }
        
        $uiScript | Out-File -FilePath $uiPath -Encoding UTF8 -Force

        $taskName = "RekordataBitLockerUI"
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$uiPath`""
        $principal = New-ScheduledTaskPrincipal -GroupId "Users"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Log "UI Premium inviata all'utente tramite Scheduled Task."
    }
    catch {
        Write-Log "Failed to trigger Premium UI: $_" "ERROR"
    }
}

function Get-BitLockerMDMPolicy {
    <#
    .SYNOPSIS
        Legge la policy BitLocker pushata da Google DM via MDM/OMA-URI.
        Il registro HKLM:\SOFTWARE\Policies\Microsoft\FVE viene scritto da Windows
        quando riceve la policy dall'MDM. La sua presenza indica che Google DM
        ha già inviato la direttiva BitLocker al dispositivo.
    #>
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    $result = @{
        PolicyPresent    = $false
        EncryptionMethod = "xts_aes256"  # Nomenclature specifica per manage-bde
    }

    try {
        if (-not (Test-Path $fvePath)) {
            Write-Log "BitLocker policy key absent (FVE). Google DM has not pushed BitLocker policy yet." "WARN"
            return $result
        }

        $result.PolicyPresent = $true
        Write-Log "BitLocker MDM policy key confirmed by Google DM."

        # Mappa OMA-URI EncryptionMethodWithXtsOs → nomenclatura manage-bde
        $methodMap = @{
            3 = "aes128"
            4 = "aes256"
            6 = "xts_aes128"
            7 = "xts_aes256"
        }

        $rawMethod = (Get-ItemProperty -Path $fvePath -ErrorAction SilentlyContinue).EncryptionMethodWithXtsOs
        if ($null -ne $rawMethod -and $methodMap.ContainsKey([int]$rawMethod)) {
            $result.EncryptionMethod = $methodMap[[int]$rawMethod]
            Write-Log "MDM Encryption method (manage-bde style): $($result.EncryptionMethod)"
        }
    }
    catch {
        Write-Log "Error reading BitLocker MDM policy from registry: $_" "ERROR"
    }

    return $result
}

function Invoke-BitLockerActivation {
    param([string]$EncryptionMethod = "xts_aes256")
    <#
    .SYNOPSIS
        Attiva BitLocker in modo silente usando manage-bde per massima compatibilità.
        Gestisce in modo idempotente protettori TPM e RecoveryPassword.
    #>
    $result = @{
        Success    = $false
        StatusNote = ""
    }

    try {
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

        # 1. CASO: SOSPESO
        if ($vol.ProtectionStatus -eq "Off" -and $vol.VolumeStatus -eq "FullyEncrypted") {
            Write-Log "BitLocker risulta SOSPESO. Ripristino protezione..."
            manage-bde -resume $env:SystemDrive | Out-Null
            $result.Success = $true
            $result.StatusNote = "resumed"
            return $result
        }

        # 2. CASO: GIÀ ATTIVO
        if ($vol.ProtectionStatus -eq "On") {
            Write-Log "BitLocker già attivo."
            if (-not ($vol.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'})) {
                Write-Log "Chiave di ripristino assente. Aggiunta in corso..."
                manage-bde -protectors -add $env:SystemDrive -RecoveryPassword | Out-Null
                $result.StatusNote = "protector_added"
            } else {
                $result.StatusNote = "already_active"
            }
            $result.Success = $true
            return $result
        }

        # 3. CASO: DISATTIVATO (Attivazione Silente)
        Write-Log "Avvio attivazione silente via manage-bde (UsedSpaceOnly=$BitlockerUsedSpaceOnly)..."
        
        # Gestione TPM
        if (-not ($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'Tpm' })) {
            Write-Log "Aggiunta protettore TPM..."
            manage-bde -protectors -add $env:SystemDrive -tpm | Out-Null
        }

        # Gestione Recovery Password
        if (-not ($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })) {
            Write-Log "Aggiunta chiave di ripristino..."
            manage-bde -protectors -add $env:SystemDrive -RecoveryPassword | Out-Null
        }

        # Commando di attivazione finale con SkipHardwareTest (attivazione LIVE)
        $cmdArgs = @("-on", $env:SystemDrive, "-EncryptionMethod", $EncryptionMethod, "-SkipHardwareTest")
        if ($BitlockerUsedSpaceOnly) { $cmdArgs += "-Used" }

        Write-Log "Running: manage-bde $($cmdArgs -join ' ')"
        $output = manage-bde.exe @cmdArgs
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Log "BitLocker attivato correttamente."
            Invoke-PremiumNotification
            $result.Success = $true
            $result.StatusNote = "activated"
        } else {
            Write-Log "Errore manage-bde ($exitCode): $output" "ERROR"
            $result.StatusNote = "activation_error"
        }
    }
    catch {
        Write-Log "BitLocker activation failed: $_" "ERROR"
        $result.StatusNote = "activation_error"
    }

    return $result
}
#endregion

#region Main Execution
try {
    Write-Log "=== Core-Ops.ps1 Starting ==="
    
    # Ensure log directory exists
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
        Write-Log "Created log directory: $LogPath"
    }
    
    # Estrazione autonoma del Segreto
    Write-Log "Initiating Secure Handoff: Reading MDM Token..."
    $b64Token = Get-RegistryValueSecure -Path $RegistryPath -Name $MDMAuthValue
    if (-not $b64Token) {
        Write-Log "MDMAuth token missing in registry. Halting Core-Ops execution." "ERROR"
        exit 1
    }

    $saObj = ConvertFrom-Base64Json -Base64String $b64Token
    if (-not $saObj -or -not $saObj.private_key) {
        Write-Log "Extracted MDMAuth token is invalid or corrupted." "ERROR"
        exit 1
    }

    # Ottenimento Access Token Google
    Write-Log "Exchanging Service Account key for Google JWT Access Token..."
    $gcpToken = New-GcpAccessToken -ServiceAccount $saObj
    
    if (-not $gcpToken) {
        Write-Log "Failed to negotiate Google Access Token. Telemetry will be disabled." "WARN"
    }

    $gcpProjectId = $saObj.project_id
    
    # Vaporizzazione del segreto originale dalla memoria
    $b64Token = $null
    $saObj.private_key = $null
    $saObj = $null

    # region BitLocker Escrow
    # Architettura a 3 step: Google DM come trigger → Attivazione silente → Escrow
    $bitlockerStatus = "skipped"
    if ($BitlockerEnabled -and $gcpToken) {
        try {
            # --- Step 1: Google DM è il trigger ---
            # La presenza del registro HKLM:\SOFTWARE\Policies\Microsoft\FVE indica
            # che Google DM ha pushato la policy BitLocker. Senza policy → skip totale.
            $mdmPolicy = Get-BitLockerMDMPolicy

            if (-not $mdmPolicy.PolicyPresent) {
                Write-Log "Google DM BitLocker policy not present on this device. Skipping activation and escrow." "WARN"
                $bitlockerStatus = "policy_absent"
            }
            else {
                Write-Log "Google DM policy confirmed (method: $($mdmPolicy.EncryptionMethod)). Proceeding with activation check..."

                # --- Step 2: Attivazione silente condizionale ---
                $activation = Invoke-BitLockerActivation -EncryptionMethod $mdmPolicy.EncryptionMethod

                if (-not $activation.Success) {
                    Write-Log "BitLocker activation step failed ($($activation.StatusNote)). Aborting escrow." "ERROR"
                    $bitlockerStatus = "activation_failed"
                }
                else {
                    Write-Log "BitLocker state OK [$($activation.StatusNote)]. Initiating Escrow to Google Drive..."

                    # --- Step 3: Escrow della chiave di ripristino ---
                    $blVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
                    $recoveryProtector = $blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }

                    if ($recoveryProtector) {
                        $keyProtectorId = $recoveryProtector.KeyProtectorId

                        # Check idempotency via registry
                        $lastSyncId = Get-RegistryValueSecure -Path $RegistryPath -Name "LastBitLockerSyncId"
                        if ($keyProtectorId -eq $lastSyncId) {
                            Write-Log "BitLocker key already synced (ID: $keyProtectorId). Skipping upload."
                            $bitlockerStatus = "already_synced"
                        }
                        else {
                            Write-Log "New or updated BitLocker key detected. Gathering hardware identifiers..."
                            $serialNumber = (Get-CimInstance Win32_Bios).SerialNumber

                            $fileName = "$($env:COMPUTERNAME)_$($blVolume.MountPoint.Replace(':',''))_BitLocker.txt"

                            # Costruzione contenuto arricchito
                            $fileContent = @"
Hostname: $($env:COMPUTERNAME)
Serial Number: $serialNumber
Disk: $($blVolume.MountPoint)
Key Protector ID: $keyProtectorId
Recovery Key: $($recoveryProtector.RecoveryPassword)
"@

                            # Upload Multi-Part
                            $uploadRes = Send-DriveUploadMultipart -FileName $fileName -Content $fileContent -FolderId $BitlockerFolderId -AccessToken $gcpToken

                            if ($uploadRes) {
                                Write-Log "BitLocker Escrow successful for disk: $($env:SystemDrive)"
                                $bitlockerStatus = "success"

                                # Salva lo stato nel registro per evitare duplicati
                                New-ItemProperty -Path $RegistryPath -Name "LastBitLockerSyncId" -Value $keyProtectorId -PropertyType String -Force | Out-Null
                            }
                            else {
                                Write-Log "BitLocker Escrow failed to upload." "ERROR"
                                $bitlockerStatus = "failed"
                            }
                        }

                        # Vaporizzazione immediata della chiave dalla memoria
                        $fileContent = $null
                        $recoveryProtector = $null
                        $blVolume = $null
                        [System.GC]::Collect()
                    }
                    else {
                        Write-Log "No RecoveryPassword protector found after activation step. Unexpected state." "ERROR"
                        $bitlockerStatus = "failed"
                    }
                }
            }
        }
        catch {
            Write-Log "Failed in BitLocker block: $_" "ERROR"
        }
    }
    # endregion
    
    # Garbage Collector: interroga WMI, non il filesystem
    Write-Log "[GC] Avvio scansione profili inattivi (soglia: $MinProfileAgeDays giorni)..."
    $staleProfiles = Get-StaleProfiles -MinAgeDays $MinProfileAgeDays
    $cleanedCount = 0

    if ($staleProfiles.Count -eq 0) {
        Write-Log "[GC] Nessun profilo candidato trovato. Sistema pulito."
    }
    else {
        Write-Log "[GC] Trovati $($staleProfiles.Count) profili candidati alla rimozione:"
        foreach ($p in $staleProfiles) {
            Write-Log "  - $($p.LocalPath.Split('\\')[-1]) | LastUse: $($p.LastUseTime) | Loaded: $($p.Loaded)"
        }

        foreach ($p in $staleProfiles) {
            if (Cleanup-Profile -ProfileInstance $p) {
                $cleanedCount++
            }
            Start-Sleep -Milliseconds 500
        }

        Write-Log "[GC] Pulizia completata. $cleanedCount profili rimossi (filesystem + registro)."
    }

    # Heartbeat Telemetry: Inviata sempre se il token è valido
    if ($TelemetryEnabled -and $gcpToken) {
        try {
            $telemetryData = @{
                deviceId        = $env:COMPUTERNAME
                timestamp       = (Get-Date).ToString("o")
                eventType       = "heartbeat_cleanup"
                profilesFound   = [int]$oldProfiles.Count
                profilesCleaned = [int]$cleanedCount
                bitlockerSync   = $bitlockerStatus
            }
            Send-FirestoreTelemetry -Data $telemetryData -AccessToken $gcpToken -ProjectId $gcpProjectId | Out-Null
        }
        catch {
            Write-Log "Failed to send heartbeat telemetry: $_" "WARN"
        }
    }
    
    Write-Log "=== Core-Ops.ps1 Completed Successfully ==="
    exit 0
}
catch {
    Write-Log "Unhandled error in Core-Ops.ps1: $_" "ERROR"
    exit 1
}
#endregion
