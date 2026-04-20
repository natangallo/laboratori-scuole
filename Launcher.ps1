<#
.SYNOPSIS
    Rekordata Windows Governance Launcher
.DESCRIPTION
    v2.3.1 - Modular Architecture (Disk-Temporary execution).
.NOTES
    Author: Rekordata Team
    Version: 2.3.1
#>

#region 1. Configuration
$BaseDir = "C:\ProgramData\Rekordata"
$LogPath = Join-Path $BaseDir "Logs"
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"

# Base URL reflects the vertical folder structure for Windows
$GitHubRepo = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/"
$ModuleBaseUrl = $GitHubRepo

# Global Headers for Cache-Busting
$GlobalHeaders = @{
    "Cache-Control" = "no-cache"
    "Pragma"        = "no-cache"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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
    $tempModPath = Join-Path $env:TEMP "Mod-${Keyword}.ps1"
    try {
        Write-Log "Fetching module '${Keyword}'..."
        $url = $ScriptUrl.Trim()
        if ($ScriptUrl -notlike "http*") {
            $url = ("${ModuleBaseUrl}${ScriptUrl}").Trim()
        }
        # Add aggressive cache-busting (nanoseconds ticks)
        $cacheBuster = [DateTime]::UtcNow.Ticks
        $urlWithCache = "$url?nocache=$cacheBuster"
        
        # Disk-based execution for robustness
        Invoke-WebRequest -Uri $urlWithCache -Headers $GlobalHeaders -OutFile $tempModPath -ErrorAction Stop
        
        if (Test-Path $tempModPath) {
            Write-Log "Executing ${Keyword} from disk (temp)..."
            $result = & $tempModPath $Context
            
            if ($result -is [PSCustomObject]) {
                return $result
            } else {
                return [PSCustomObject]@{ Module=$Keyword; Success=$true; Status="Done" }
            }
        }
    }
    catch {
        Write-Log "Module ${Keyword} failed: $_" "ERROR"
        return [PSCustomObject]@{ Module=$Keyword; Success=$false; Status="Error"; Details=@{ Error=$_.ToString() } }
    }
    finally {
        if (Test-Path $tempModPath) { Remove-Item $tempModPath -Force -ErrorAction SilentlyContinue }
    }
}

function Test-ModuleCooldown {
    param($Mod)
    if ($Mod.forceRun) { return $false }
    $path = "$RegistryPath\Modules\$($Mod.keyword)"
    $val = Get-RegistryValueSecure -Path $path -Name "LastRun"
    if ($null -eq $val -or -not $Mod.cooldownMinutes) { return $false }
    $lastRun = [DateTime]::Parse($val)
    return $lastRun.AddMinutes($Mod.cooldownMinutes) -gt (Get-Date)
}

function Update-ModuleRegistry {
    param([string]$Keyword, [bool]$Success)
    $path = "$RegistryPath\Modules\$Keyword"
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    Set-ItemProperty -Path $path -Name "LastRun" -Value (Get-Date).ToString("o")
    Set-ItemProperty -Path $path -Name "Status" -Value (if($Success){"Success"}else{"Failed"})
}
#endregion

# region 4. Main Orchestration
try {
    Write-Log "=== Launcher v2.3.1 Starting (Disk-Mode) ==="

    $b64Token = Get-RegistryValueSecure -Path $RegistryPath -Name $MDMAuthValue
    if (-not $b64Token) { throw "Auth missing." }
    $saObj = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Token)) | ConvertFrom-Json

    $gcpToken = New-GcpAccessToken -ServiceAccount $saObj
    $projectId = $saObj.project_id

    # Get manifest with cache busting
    $manifestUrl = ("${GitHubRepo}manifest.json").Trim() + "?nocache=$([DateTime]::UtcNow.Ticks)"
    $manifest = Invoke-RestMethod -Uri $manifestUrl -Headers $GlobalHeaders -ErrorAction Stop
    $results = @()

    foreach ($mod in $manifest.modules) {
        if ($mod.enabled -and -not (Test-ModuleCooldown -Mod $mod)) {
            $ctx = @{ AccessToken=$gcpToken; ProjectId=$projectId; RegistryPath=$RegistryPath; LogPath=$LogPath }
            if ($mod.config) { 
                foreach ($prop in $mod.config.psobject.Properties) { 
                    $ctx[$prop.Name] = $prop.Value 
                } 
            }

            $res = Invoke-RemoteModule -Keyword $mod.keyword -ScriptUrl $mod.scriptUrl -Context $ctx
            $results += $res
            Update-ModuleRegistry -Keyword $mod.keyword -Success $res.Success
        }
    }

    if ($gcpToken -and $results.Count -gt 0) {
        $payload = @{
            deviceId = $env:COMPUTERNAME; timestamp=(Get-Date).ToString("o")
            summary  = @{ total=$results.Count; success=($results | Where-Object { $_.Success }).Count }
            details  = $results
        }
        Send-Telemetry -AccessToken $gcpToken -ProjectId $projectId -Data $payload | Out-Null
    }
    Write-Log "=== Launcher v2.3.1 Completed ==="
}
catch {
    Write-Log "Launcher Fatal: $_" "ERROR"
}
