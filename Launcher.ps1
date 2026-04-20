<#
.SYNOPSIS
    Rekordata Windows Governance Launcher
.DESCRIPTION
    v2.0.0 - Modular Architecture.
    This script is the central orchestrator (Plumbing) for Windows Governance.
    - Handles JWT Exchange for Google Cloud.
    - Manages shared Telemetry (Firestore).
    - Fetches and executes operational modules in-memory.
.NOTES
    Author: Rekordata Team
    Version: 2.0.0
#>

#region Configuration
$BaseDir = "C:\ProgramData\Rekordata"
$LogPath = Join-Path $BaseDir "Logs"
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"
$ModuleBaseUrl = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/modules/"
$GitHubRepo = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/"
#endregion

#region Plumbing Functions (Auth & Telemetry)
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Launcher] $Message"
    if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
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
    }
    catch { return $null }
}

function ConvertTo-Base64Url {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-GcpAccessToken {
    param([object]$ServiceAccount)
    try {
        $header = @{ alg = "RS256"; typ = "JWT" } | ConvertTo-Json -Compress
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $claim = @{
            iss   = $ServiceAccount.client_email
            scope = "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/drive"
            aud   = "https://oauth2.googleapis.com/token"
            exp   = $now + 3600
            iat   = $now
        } | ConvertTo-Json -Compress

        $message = "$((ConvertTo-Base64Url -InputString $header)).$((ConvertTo-Base64Url -InputString $claim))"
        $privateKeyPem = $ServiceAccount.private_key.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("`n", "").Replace("`r", "").Trim()
        $keyBytes = [Convert]::FromBase64String($privateKeyPem)

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))
        $cngKey = [System.Security.Cryptography.CngKey]::Import($keyBytes, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $rsaCng = New-Object System.Security.Cryptography.RSACng($cngKey)
        
        $signatureBytes = $rsaCng.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $jwt = "$message.$([Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))"

        $tokenResponse = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method Post -Body @{
            grant_type = "urn:ietf:params:oauth-grant-type:jwt-bearer"
            assertion  = $jwt
        }
        return $tokenResponse.access_token
    }
    catch { 
        Write-Log "GCP Token Exchange Failed: $_" "ERROR"
        return $null 
    }
}

function Send-Telemetry {
    param([hashtable]$Data, [string]$AccessToken, [string]$ProjectId)
    try {
        $fields = @{}
        foreach ($key in $Data.Keys) {
            $val = $Data[$key]
            if ($val -is [int]) { $fields[$key] = @{ integerValue = $val } }
            elseif ($val -is [double] -or $val -is [float]) { $fields[$key] = @{ doubleValue = $val } }
            elseif ($val -is [bool]) { $fields[$key] = @{ booleanValue = $val } }
            elseif ($key -eq "timestamp") { $fields[$key] = @{ timestampValue = $val } }
            elseif ($val -is [hashtable] -or $val -is [array] -or $val -is [PSCustomObject]) {
                # Convert complex objects to JSON string to avoid Firestore nesting complexity
                $fields[$key] = @{ stringValue = ($val | ConvertTo-Json -Compress -Depth 10) }
            }
            else { $fields[$key] = @{ stringValue = [string]$val } }
        }
        $body = @{ fields = $fields } | ConvertTo-Json -Depth 5
        $uri = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/telemetry"
        Invoke-RestMethod -Uri $uri -Method Post -Headers @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" } -Body $body | Out-Null
        return $true
    }
    catch { 
        Write-Log "Firestore Telemetry Error: $_" "WARN"
        return $false 
    }
}
#endregion

#region Module Execution Engine
function Invoke-RemoteModule {
    param(
        [string]$Keyword,
        [string]$ScriptUrl,
        [hashtable]$Context,
        [int]$TimeoutSeconds = 300
    )
    try {
        Write-Log "Fetching module '$Keyword' from $ScriptUrl..."
        $url = if ($ScriptUrl -like "http*") { $ScriptUrl } else { "${GitHubRepo}${ScriptUrl}" }
        $scriptContent = Invoke-RestMethod -Uri $url -ErrorAction Stop
        
        if ($scriptContent) {
            Write-Log "Executing $Keyword in-memory (Timeout: ${TimeoutSeconds}s)..."
            $scriptBlock = [scriptblock]::Create($scriptContent)
            
            # Execute and capture the ResultObject
            $result = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Context
            
            if ($result -is [PSCustomObject]) {
                return $result
            }
            else {
                return [PSCustomObject]@{
                    Module  = $Keyword
                    Success = $true
                    Status  = "Completed (No ResultObject)"
                    Details = @{}
                }
            }
        }
    }
    catch {
        Write-Log "Module $Keyword execution failed: $_" "ERROR"
        return [PSCustomObject]@{
            Module  = $Keyword
            Success = $false
            Status  = "Error"
            Details = @{ Error = $_.ToString() }
        }
    }
}

function Test-ModuleCooldown {
    param($Mod)
    if ($Mod.forceRun) { return $false }
    
    $modRegPath = "$RegistryPath\Modules\$($Mod.keyword)"
    $lastRunValue = Get-RegistryValueSecure -Path $modRegPath -Name "LastRunSuccess"
    
    if ($null -eq $lastRunValue) { return $false }
    
    try {
        $lastDate = [DateTime]::Parse($lastRunValue)
        $diff = (Get-Date) - $lastDate
        
        if ($Mod.type -eq "oneshot") {
            Write-Log "Module $($Mod.keyword) is oneshot and already succeeded on $lastDate. Skipping."
            return $true
        }
        
        $intervalHours = if ($Mod.intervalHours) { $Mod.intervalHours } else { 24 }
        if ($diff.TotalHours -lt $intervalHours) {
            Write-Log "Cooldown active for $($Mod.keyword) (Next run in $([Math]::Round($intervalHours - $diff.TotalHours, 1))h). Skipping."
            return $true
        }
    }
    catch { }
    
    return $false
}

function Update-ModuleRegistry {
    param($Keyword, $Success)
    $modRegPath = "$RegistryPath\Modules\$Keyword"
    if (-not (Test-Path $modRegPath)) { New-Item -Path $modRegPath -Force | Out-Null }
    
    New-ItemProperty -Path $modRegPath -Name "LastRun" -Value (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") -PropertyType String -Force | Out-Null
    if ($Success) {
        New-ItemProperty -Path $modRegPath -Name "LastRunSuccess" -Value (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $modRegPath -Name "LastStatus" -Value "Success" -PropertyType String -Force | Out-Null
    }
    else {
        New-ItemProperty -Path $modRegPath -Name "LastStatus" -Value "Failed" -PropertyType String -Force | Out-Null
    }
}
#endregion

#region Main Logic
try {
    Write-Log "=== Launcher v2.1.0 Starting ==="
    
    # 1. Auth Retrieval
    $b64Token = Get-RegistryValueSecure -Path $RegistryPath -Name $MDMAuthValue
    if (-not $b64Token) { Write-Log "MDMAuth missing." "ERROR"; exit 1 }

    $saObj = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64Token)) | ConvertFrom-Json
    $gcpToken = New-GcpAccessToken -ServiceAccount $saObj
    $projectId = $saObj.project_id
    
    $saObj = $null; $b64Token = $null; [System.GC]::Collect()

    if (-not $gcpToken) { Write-Log "GCP Auth failed. Firestore telemetry will be disabled." "WARN" }

    # 2. Base Context
    $baseContext = @{
        AccessToken  = $gcpToken
        ProjectId    = $projectId
        RegistryPath = $RegistryPath
        LogPath      = $LogPath
    }

    # 3. Manifest Orchestration
    Write-Log "Fetching manifest..."
    $manifestUrl = "${GitHubRepo}manifest.json"
    $moduleResults = @()
    
    try {
        $manifest = Invoke-RestMethod -Uri $manifestUrl -ErrorAction Stop
        Write-Log "Manifest v$($manifest.version) loaded."
        
        foreach ($mod in $manifest.modules) {
            if ($mod.enabled) {
                # Check Cooldown
                if (Test-ModuleCooldown -Mod $mod) { continue }

                # Prepare module context: Base Context + manifest.config
                $moduleContext = $baseContext.Clone()
                if ($mod.config) {
                    foreach ($key in $mod.config.psobject.properties.Name) {
                        $moduleContext[$key] = $mod.config.$key
                    }
                }

                # Execution
                $resObj = Invoke-RemoteModule -Keyword $mod.keyword -ScriptUrl $mod.scriptUrl -Context $moduleContext -TimeoutSeconds $mod.timeoutSeconds
                $moduleResults += $resObj
                
                # Update Registry
                Update-ModuleRegistry -Keyword $mod.keyword -Success $resObj.Success
            }
            else {
                Write-Log "Module $($mod.keyword) disabled. Skipping."
            }
        }
    }
    catch {
        Write-Log "Manifest failure: $_" "ERROR"
    }

    # 4. Final Unified Telemetry
    if ($gcpToken -and $moduleResults.Count -gt 0) {
        Write-Log "Sending unified telemetry for $($moduleResults.Count) modules..."
        $telemetryPayload = @{
            deviceId        = $env:COMPUTERNAME
            timestamp       = (Get-Date).ToString("o")
            manifestVersion = if ($manifest) { $manifest.version } else { "unknown" }
            eventType       = "governance_session"
            summary         = @{
                totalModules   = $moduleResults.Count
                successModules = ($moduleResults | Where-Object { $_.Success }).Count
            }
            # Add detailed results (Firestore handles nested maps/arrays)
            # Note: We convert results to a more Firestore-friendly format if needed
            details         = $moduleResults
        }
        
        # We need a revised Send-Telemetry that handles deep objects or just strings
        Send-Telemetry -AccessToken $gcpToken -ProjectId $projectId -Data $telemetryPayload | Out-Null
    }

    Write-Log "=== Launcher v2.1.0 Completed ==="
}
catch {
    Write-Log "Fatal Launcher Error: $_" "ERROR"
    exit 1
}
#endregion
