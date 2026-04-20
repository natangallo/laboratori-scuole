# .SYNOPSIS
#     Rekordata Windows Governance Launcher
# .DESCRIPTION
#     v2.4.1 - Strict Zero-Disk Modular Architecture (Scope Fixed).
# .NOTES
#     Author: Rekordata Team
#     Version: 2.4.1

#region 1. Configuration
$global:BaseDir = "C:\ProgramData\Rekordata"
$global:LogPath = Join-Path $global:BaseDir "Logs"
$global:RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$global:MDMAuthValue = "MDMAuth"

$global:GitHubRepo = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/"
$global:ModuleBaseUrl = $global:GitHubRepo

$global:GlobalHeaders = @{
    "Cache-Control" = "no-cache"
    "Pragma"        = "no-cache"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Launcher] $Message"
    if (-not (Test-Path $global:LogPath)) { try { New-Item -ItemType Directory -Path $global:LogPath -Force | Out-Null } catch {} }
    Add-Content -Path (Join-Path $global:LogPath "Governance.log") -Value $logEntry
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
        $header = ConvertTo-Base64Url -InputString (@{ alg = "RS256"; typ = "JWT" } | ConvertTo-Json -Compress)
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $claim = ConvertTo-Base64Url -InputString (@{
            iss   = $ServiceAccount.client_email
            scope = "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/drive"
            aud   = "https://oauth2.googleapis.com/token"
            exp   = $now + 3600; iat = $now
        } | ConvertTo-Json -Compress)

        $keyBytes = [Convert]::FromBase64String($ServiceAccount.private_key.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("`n", "").Replace("`r", "").Trim())
        $cngKey = [System.Security.Cryptography.CngKey]::Import($keyBytes, [System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        $rsaCng = New-Object System.Security.Cryptography.RSACng($cngKey)
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$header.$claim"))
        $sig = [Convert]::ToBase64String($rsaCng.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        $res = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method Post -Body @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion  = "$header.$claim.$sig"
        }
        return $res.access_token
    } catch { return $null }
}

function Send-Telemetry {
    param([string]$AccessToken, [string]$ProjectId, [hashtable]$Data)
    try {
        $body = @{ fields = @{
            deviceId  = @{ stringValue = $Data.deviceId }
            timestamp = @{ timestampValue = $Data.timestamp }
            summary   = @{ mapValue = @{ fields = @{
                total   = @{ integerValue = $Data.summary.total }
                success = @{ integerValue = $Data.summary.success }
            } } }
            details   = @{ arrayValue = @{ values = ($Data.details | ForEach-Object {
                @{ mapValue = @{ fields = @{
                    module  = @{ stringValue = $_.Module }
                    success = @{ booleanValue = $_.Success }
                    status  = @{ stringValue = $_.Status }
                } } }
            }) } }
        } } | ConvertTo-Json -Depth 10

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
        Write-Log "Fetching module '${Keyword}'..."
        $url = $ScriptUrl.Trim()
        if ($ScriptUrl -notlike "http*") {
            if ($global:ModuleBaseUrl -notlike "*/") { $global:ModuleBaseUrl += "/" }
            $url = ("{0}{1}" -f $global:ModuleBaseUrl, $ScriptUrl).Trim()
        }
        $cacheBuster = [DateTime]::UtcNow.Ticks
        $urlWithCache = $url + "?nocache=" + $cacheBuster
        
        # Zero-Disk Download using .NET WebClient for perfect string encoding bypass Invoke-RestMethod truncation
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("Cache-Control", "no-cache")
        $scriptContent = $webClient.DownloadString($urlWithCache)
        
        if ($scriptContent) {
            Write-Log "Executing ${Keyword} in-memory (Zero-Disk)..."
            $scriptBlock = [scriptblock]::Create($scriptContent)
            $result = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Context
            if ($result -is [PSCustomObject]) { return $result }
            else { return [PSCustomObject]@{ Module=$Keyword; Success=$true; Status="Done" } }
        }
    }
    catch {
        Write-Log "Module ${Keyword} failed: $_" "ERROR"
        return [PSCustomObject]@{ Module=$Keyword; Success=$false; Status="Error"; Details=@{ Error=$_.ToString() } }
    }
}

function Test-ModuleCooldown {
    param($Mod)
    $isForce = if($Mod.psobject.Properties['forceRun']) { $Mod.forceRun } else { $false }
    if ($isForce -eq $true) { 
        Write-Log "Module $($Mod.keyword) has forceRun enabled. Cooldown ignored."
        return $false 
    }
    
    $path = "$global:RegistryPath\Modules\$($Mod.keyword)"
    $val = Get-RegistryValueSecure -Path $path -Name "LastRun"
    if ($null -eq $val -or -not $Mod.cooldownMinutes) { return $false }
    $lastRun = [DateTime]::Parse($val)
    return $lastRun.AddMinutes($Mod.cooldownMinutes) -gt (Get-Date)
}

function Update-ModuleRegistry {
    param([string]$Keyword, [bool]$Success)
    $path = "$global:RegistryPath\Modules\$Keyword"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "LastRun" -Value (Get-Date).ToString("o")
    
    $statusValue = "Failed"
    if ($Success) { $statusValue = "Success" }
    
    Set-ItemProperty -Path $path -Name "Status" -Value $statusValue
}
#endregion

# region 4. Main Orchestration
try {
    Write-Log "=== Launcher v2.4.1 Starting (Strict Zero-Disk) ==="

    $b64Token = Get-RegistryValueSecure -Path $global:RegistryPath -Name $global:MDMAuthValue
    if (-not $b64Token) { throw "Auth missing." }
    $saObj = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Token)) | ConvertFrom-Json

    $gcpToken = New-GcpAccessToken -ServiceAccount $saObj
    $projectId = $saObj.project_id

    # Get manifest with cache busting
    $manifestUrl = ("{0}manifest.json" -f $global:GitHubRepo).Trim() + "?nocache=" + [DateTime]::UtcNow.Ticks
    $manifest = Invoke-RestMethod -Uri $manifestUrl -Headers $global:GlobalHeaders -ErrorAction Stop
    
    Write-Log "Manifest Fetched. Version: $($manifest.version)"

    $results = @()
    foreach ($mod in $manifest.modules) {
        if (-not $mod.enabled) {
            Write-Log "Module $($mod.keyword) is disabled. Skipping."
            continue
        }
        if (Test-ModuleCooldown -Mod $mod) {
            Write-Log "Module $($mod.keyword) is in cooldown. Skipping."
            continue
        }

        $ctx = @{ AccessToken=$gcpToken; ProjectId=$projectId; RegistryPath=$global:RegistryPath; LogPath=$global:LogPath }
        if ($mod.config) { foreach ($p in $mod.config.psobject.Properties) { $ctx[$p.Name] = $p.Value } }

        $res = Invoke-RemoteModule -Keyword $mod.keyword -ScriptUrl $mod.scriptUrl -Context $ctx
        $results += $res
        Update-ModuleRegistry -Keyword $mod.keyword -Success $res.Success
    }

    if ($gcpToken -and $results.Count -gt 0) {
        $payload = @{
            deviceId = $env:COMPUTERNAME; timestamp=(Get-Date).ToString("o")
            summary  = @{ total=$results.Count; success=($results | Where-Object { $_.Success }).Count }
            details  = $results
        }
        Send-Telemetry -AccessToken $gcpToken -ProjectId $projectId -Data $payload | Out-Null
    }
    Write-Log "=== Launcher v2.4.1 Completed ==="
}
catch {
    Write-Log "Launcher Fatal: $_" "ERROR"
}
