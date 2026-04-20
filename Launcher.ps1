<#
.SYNOPSIS
    Rekordata Windows Governance Launcher
.DESCRIPTION
    v2.2.5 - Modular Architecture (Final Auth & BDE Debug).
.NOTES
    Author: Rekordata Team
    Version: 2.2.5
#>

#region 1. Internal Logging & TLS
$LogPath = "C:\ProgramData\Rekordata\Logs\Governance.log"
if (-not (Test-Path "C:\ProgramData\Rekordata\Logs")) { New-Item -Path "C:\ProgramData\Rekordata\Logs" -ItemType Directory -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Stamp] [$Level] [Launcher] $Message"
    Add-Content -Path $LogPath -Value $Line
    Write-Host $Line
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#region 2. Crypto & Auth (GCP JWT)
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"

function Get-RegistryValueSecure {
    param($Path, $Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

function New-GcpAccessToken {
    param([string]$B64Json)
    try {
        $Auth = $B64Json | ConvertFrom-Json
        if (-not $Auth.client_email -or -not $Auth.private_key) { throw "Invalid Auth JSON" }

        # Header
        $Header = @{ alg = "RS256"; typ = "JWT" }
        $HeaderB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($Header | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        # Claim
        $Now = [Math]::Floor([decimal](Get-Date -UFormat %s))
        $Claim = @{
            iss   = $Auth.client_email
            scope = "https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/logging.write"
            aud   = "https://oauth2.googleapis.com/token"
            iat   = $Now
            exp   = $Now + 3600
        }
        $ClaimB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($Claim | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+', '-').Replace('/', '_')

        # Sign
        $message = "$HeaderB64.$ClaimB64"
        $privateKey = $Auth.private_key -replace "-----BEGIN PRIVATE KEY-----", "" -replace "-----END PRIVATE KEY-----", "" -replace "\s", ""
        $privateKeyBytes = [Convert]::FromBase64String($privateKey)
        
        $rsaCng = New-Object System.Security.Cryptography.RSACng
        $rsaCng.ImportPkcs8PrivateKey($privateKeyBytes, [out]$null)
        
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($message))
        $signatureBytes = $rsaCng.SignHash($hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $jwt = "$message.$([Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))"

        # Fix: PS 5.1 might send colons raw. Google expects them URL-encoded.
        # Hardcoding the encoded version of "urn:ietf:params:oauth-grant-type:jwt-bearer"
        $encodedGrant = "urn%3Aietf%3Aparams%3Aoauth-grant-type%3Ajwt-bearer"
        $body = "grant_type=$($encodedGrant)&assertion=$($jwt)"
        
        $tokenResponse = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" `
            -Method Post `
            -ContentType "application/x-www-form-urlencoded" `
            -Body $body
        return $tokenResponse.access_token
    }
    catch {
        $errorMessage = $_.ToString()
        $bodyError = ""
        if ($_.Exception -and $_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $bodyError = $reader.ReadToEnd()
        }
        Write-Log "GCP Token Exchange Failed: $errorMessage | Body: $bodyError" "ERROR"
        return $null
    }
}

#region 3. Telemetry (Firestore Minimal)
function Send-Telemetry {
    param([string]$AccessToken, [string]$ProjectId, [hashtable]$Data)
    try {
        $Id = $env:COMPUTERNAME
        $Url = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/telemetry/$Id"
        
        # Convert simple hashtable to Firestore fields
        $fields = @{}
        foreach ($key in $Data.Keys) {
            $val = $Data[$key]
            if ($val -is [bool]) { $fields[$key] = @{ booleanValue = $val } }
            elseif ($val -match '^\d+$') { $fields[$key] = @{ integerValue = $val } }
            else { $fields[$key] = @{ stringValue = $val.ToString() } }
        }
        
        $Payload = @{ fields = $fields } | ConvertTo-Json -Depth 10
        $Headers = @{ Authorization = "Bearer $AccessToken" }
        
        return Invoke-RestMethod -Uri $Url -Method Patch -Headers $Headers -ContentType "application/json" -Body $Payload
    }
    catch {
        Write-Log "Telemetry Sync Failed: $_" "WARNING"
    }
}

#region 4. Main Orchestration
try {
    Write-Log "=== Launcher v2.2.5 Starting ==="
    
    $b64Token = Get-RegistryValueSecure -Path $RegistryPath -Name $MDMAuthValue
    if (-not $b64Token) { throw "Auth missing." }
    
    $authJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Token))
    $projectId = ($authJson | ConvertFrom-Json).project_id
    
    Write-Log "Exchanging JWT for Google Access Token..."
    $gcpToken = New-GcpAccessToken -B64Json $authJson
    
    if (-not $gcpToken) {
        Write-Log "Execution halted: Could not obtain GCP Token." "ERROR"
        exit 1
    }

    # Fetch Manifest (Modules to run)
    $GitHubRepo = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/"
    $ManifestUrl = "$GitHubRepo" + "manifest.json?nocache=" + (Get-Date -UFormat %s)
    
    Write-Log "Fetching Manifest..."
    $manifest = Invoke-RestMethod -Uri $ManifestUrl
    
    $payload = @{
        last_run = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        version = "2.2.5"
        modules = ""
    }

    foreach ($mod in $manifest.modules) {
        if ($mod.enabled) {
            Write-Log "Fetching module '$($mod.name)'..."
            $modContent = Invoke-RestMethod -Uri "$GitHubRepo$($mod.path)?nocache=$(Get-Date -UFormat %s)"
            Write-Log "Executing $($mod.name) in-memory..."
            
            # Pass common context (Token, ProjectId)
            $context = @{
                AccessToken = $gcpToken
                ProjectId   = $projectId
            }
            
            Invoke-Expression $modContent
            $payload.modules += "$($mod.name):OK; "
        }
        else {
            Write-Log "Module '$($mod.name)' disabled."
        }
    }

    if ($gcpToken) {
        Write-Log "Syncing Telemetry to Firestore..."
        # Add basic hardware info
        $cs = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem
        $payload.model = $cs.Model
        $payload.os = $os.Caption
        $payload.ram = [math]::Round($cs.TotalPhysicalMemory / 1GB, 0).ToString() + "GB"
        
        Send-Telemetry -AccessToken $gcpToken -ProjectId $projectId -Data $payload | Out-Null
    }
    Write-Log "=== Launcher v2.2.5 Completed ==="
}
catch {
    Write-Log "Launcher Fatal: $_" "ERROR"
}
#endregion
