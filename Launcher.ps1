<#
.SYNOPSIS
    Rekordata Windows Governance Launcher
.DESCRIPTION
    v2.2.0 - Modular Architecture (L00 Aligned).
    This script is the central orchestrator (Plumbing) for Windows Governance.
    - Executed in-memory by the Bootstrap-Agent.
    - Handles JWT Exchange for Google Cloud.
    - Manages shared Telemetry (Firestore).
    - Fetches and executes operational modules (manifest-driven).
.NOTES
    Author: Rekordata Team
    Version: 2.2.0
#>

#region 1. Configuration
$BaseDir = "C:\ProgramData\Rekordata"
$LogPath = Join-Path $BaseDir "Logs"
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"
# Base URL reflects the vertical folder structure for Windows
$GitHubRepo = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/"
$ModuleBaseUrl = $GitHubRepo # Modules will be fetched relative to this (e.g., modules/Script.ps1)
#endregion

#region 2. Plumbing Functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Launcher] $Message"
    if (-not (Test-Path $LogPath)) { try { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null } catch {} }
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
        $baseKey.Close(); return $null
    } catch { return $null }
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
            elseif ($val -is [bool]) { $fields[$key] = @{ booleanValue = $val } }
            elseif ($key -eq "timestamp") { $fields[$key] = @{ timestampValue = $val } }
            elseif ($val -is [hashtable] -or $val -is [array] -or $val -is [PSCustomObject]) {
                $fields[$key] = @{ stringValue = ($val | ConvertTo-Json -Compress -Depth 10) }
            }
            else { $fields[$key] = @{ stringValue = [string]$val } }
        }
        $body = @{ fields = $fields } | ConvertTo-Json -Depth 5
        $uri = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/telemetry"
        Invoke-RestMethod -Uri $uri -Method Post -Headers @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" } -Body $body | Out-Null
        return $true
    } catch { return $false }
}
#endregion

#region 3. Execution Engine
function Invoke-RemoteModule {
    param([string]$Keyword, [string]$ScriptUrl, [hashtable]$Context)
    try {
        Write-Log "Fetching module '$Keyword'..."
        $url = if ($ScriptUrl -like "http*") { $ScriptUrl } else { "${ModuleBaseUrl}${ScriptUrl}" }
        $scriptContent = Invoke-RestMethod -Uri $url -ErrorAction Stop
        
        if ($scriptContent) {
            Write-Log "Executing $Keyword in-memory..."
            $scriptBlock = [scriptblock]::Create($scriptContent)
            $result = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Context
            
            return if ($result -is [PSCustomObject]) { $result } else { [PSCustomObject]@{ Module=$Keyword; Success=$true; Status="Done" } }
        }
    }
    catch {
        Write-Log "Module $Keyword failed: $_" "ERROR"
        return [PSCustomObject]@{ Module=$Keyword; Success=$false; Status="Error"; Details=@{ Error=$_.ToString() } }
    }
}

function Test-ModuleCooldown {
    param($Mod)
    if ($Mod.forceRun) { return $false }
    $lastRun = Get-RegistryValueSecure -Path "$RegistryPath\Modules\$($Mod.keyword)" -Name "LastRunSuccess"
    if (-not $lastRun) { return $false }
    try {
        $diff = (Get-Date) - [DateTime]::Parse($lastRun)
        $limit = if ($Mod.intervalHours) { $Mod.intervalHours } else { 24 }
        return ($diff.TotalHours -lt $limit)
    } catch { return $false }
}

function Update-ModuleRegistry {
    param($Keyword, $Success)
    $reg = "$RegistryPath\Modules\$Keyword"
    if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
    New-ItemProperty -Path $reg -Name "LastRun" -Value (Get-Date).ToString("o") -PropertyType String -Force | Out-Null
    if ($Success) { New-ItemProperty -Path $reg -Name "LastRunSuccess" -Value (Get-Date).ToString("o") -PropertyType String -Force | Out-Null }
}
#endregion

#region 4. Main Orchestration
try {
    Write-Log "=== Launcher v2.2.0 Starting ==="
    
    $b64Token = Get-RegistryValueSecure -Path $RegistryPath -Name $MDMAuthValue
    if (-not $b64Token) { throw "Auth missing." }

    $saObj = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64Token)) | ConvertFrom-Json
    $gcpToken = New-GcpAccessToken -ServiceAccount $saObj
    $projectId = $saObj.project_id
    
    $manifest = Invoke-RestMethod -Uri "${GitHubRepo}manifest.json" -ErrorAction Stop
    $results = @()
    
    foreach ($mod in $manifest.modules) {
        if ($mod.enabled -and -not (Test-ModuleCooldown -Mod $mod)) {
            $ctx = @{ AccessToken=$gcpToken; ProjectId=$projectId; RegistryPath=$RegistryPath; LogPath=$LogPath }
            if ($mod.config) { foreach ($p in $mod.config.psobject.properties.Name) { $ctx[$p] = $mod.config.$p } }
            
            $res = Invoke-RemoteModule -Keyword $mod.keyword -ScriptUrl $mod.scriptUrl -Context $ctx
            $results += $res
            Update-ModuleRegistry -Keyword $mod.keyword -Success $res.Success
        }
    }

    if ($gcpToken -and $results.Count -gt 0) {
        $payload = @{
            deviceId = $env:COMPUTERNAME; timestamp=(Get-Date).ToString("o")
            summary = @{ total=$results.Count; success=($results | Where-Object { $_.Success }).Count }
            details = $results
        }
        Send-Telemetry -AccessToken $gcpToken -ProjectId $projectId -Data $payload | Out-Null
    }
    Write-Log "=== Launcher v2.2.0 Completed ==="
}
catch {
    Write-Log "Launcher Fatal: $_" "ERROR"
}
#endregion
