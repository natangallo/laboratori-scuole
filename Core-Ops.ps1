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
$MinProfileAgeDays = 30  # Profiles older than this are candidates for cleanup
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"
$MDMAuthValue = "MDMAuth"
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
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            if ($value -and $value.${Name}) {
                return $value.${Name}
            }
        }
        return $null
    } catch {
        Write-Log "Failed to read registry value ${Path}\${Name}: $_" "ERROR"
        return $null
    }
}

function ConvertFrom-Base64Json {
    param([string]$Base64String)
    try {
        $bytes = [System.Convert]::FromBase64String($Base64String)
        $json = [System.Text.Encoding]::UTF8.GetString($bytes)
        return ConvertFrom-Json $json
    } catch {
        Write-Log "Failed to convert MDMAuth to JSON: $_" "ERROR"
        return $null
    }
}

function ConvertTo-Base64Url {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $b64 = [Convert]::ToBase64String($bytes)
    return $b64.TrimEnd('=').Replace('+','-').Replace('/','_')
}

function New-GcpAccessToken {
    param([object]$ServiceAccount)
    
    try {
        # 1. Prepare Header and Claim
        $header = @{ alg = "RS256"; typ = "JWT" } | ConvertTo-Json -Compress
        
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $claim = @{
            iss = $ServiceAccount.client_email
            scope = "https://www.googleapis.com/auth/datastore"
            aud = "https://oauth2.googleapis.com/token"
            exp = $now + 3600
            iat = $now
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
        $b64Signature = [Convert]::ToBase64String($signatureBytes).TrimEnd('=').Replace('+','-').Replace('/','_')

        # 4. Build JWT and Request Access Token
        $jwt = "$message.$b64Signature"
        $tokenResponse = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method Post -Body @{
            grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
            assertion = $jwt
        }

        # Cleanup
        $rsaCng.Dispose()
        $cngKey.Dispose()

        return $tokenResponse.access_token
    } catch {
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
                deviceId = @{ stringValue = $Data.deviceId }
                timestamp = @{ timestampValue = $Data.timestamp }
                eventType = @{ stringValue = $Data.eventType }
                profilesFound = @{ integerValue = $Data.profilesFound }
                profilesCleaned = @{ integerValue = $Data.profilesCleaned }
            }
        } | ConvertTo-Json -Depth 5

        # Collection 'telemetry', document ID auto-generated
        $uri = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/telemetry"
        
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
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

function Get-OlderProfiles {
    param([string]$Path, [int]$MinAgeDays)
    try {
        $cutoffDate = (Get-Date).AddDays(-$MinAgeDays)
        $profiles = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | 
        Where-Object {
            # Skip default and system profiles
            $_.Name -notin @("Default", "Default User", "All Users", "Public", "Administrator", "ladmin") -and
            # Check if profile is older than cutoff
            ($_.CreationTime -lt $cutoffDate)
        }
        return $profiles
    }
    catch {
        Write-Log "Error getting older profiles: $_" "ERROR"
        return @()
    }
}

function Cleanup-Profile {
    param([System.IO.DirectoryInfo]$Profile)
    try {
        Write-Log "Cleaning up profile: $($Profile.Name)"
        
        # In a real implementation, you might:
        # 1. Check if user is currently logged in
        # 2. Check if profile has active processes
        # 3. Archive important data before deletion
        # 4. Then delete the profile
        
        # Live Execution: Rimuove i dati in modo forzato
        Write-Log "Erasing profile footprint: $($Profile.FullName)" "WARN"
        
        try {
            Remove-Item -Path $Profile.FullName -Recurse -Force -ErrorAction Stop
            Write-Log "Profile successfully erased."
            return $true
        } catch {
            Write-Log "Partial failure or locked files during cleanup: $_" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to cleanup profile $($Profile.Name): $_" "ERROR"
        return $false
    }
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
    
    # Get profiles older than threshold
    Write-Log "Checking for profiles older than $MinProfileAgeDays days..."
    $oldProfiles = Get-OlderProfiles -Path $ProfilePath -MinAgeDays $MinProfileAgeDays
    
    if ($oldProfiles.Count -eq 0) {
        Write-Log "No profiles found older than $MinProfileAgeDays days"
    }
    else {
        Write-Log "Found $($oldProfiles.Count) profiles older than $MinProfileAgeDays days:"
        foreach ($profile in $oldProfiles) {
            Write-Log "  - $($profile.Name) (created: $($profile.CreationTime))"
        }
        
        # Process each profile
        $cleanedCount = 0
        foreach ($profile in $oldProfiles) {
            if (Cleanup-Profile -Profile $profile) {
                $cleanedCount++
            }
            Start-Sleep -Milliseconds 500  # Small delay between operations
        }
        
        Write-Log "Cleanup complete. $($cleanedCount) profiles processed."
    }

    # Heartbeat Telemetry: Inviata sempre se il token è valido
    if ($TelemetryEnabled -and $gcpToken) {
        try {
            $telemetryData = @{
                deviceId        = $env:COMPUTERNAME
                timestamp       = (Get-Date + (Get-Date).GetUtcOffset()).ToString("o")
                eventType       = "heartbeat_cleanup"
                profilesFound   = [int]$oldProfiles.Count
                profilesCleaned = [int]$cleanedCount
            }
            Send-FirestoreTelemetry -Data $telemetryData -AccessToken $gcpToken -ProjectId $gcpProjectId | Out-Null
        } catch {
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
