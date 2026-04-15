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

function Send-Telemetry {
    param([hashtable]$Data)
    if (-not $TelemetryEnabled) { return $false }
    
    try {
        # Add timestamp if not provided
        if (-not $Data.timestamp) {
            $Data.timestamp = (Get-Date).ToString("o")
        }
        
        # Add script identifier
        $Data.script = "Core-Ops"
        
        # In a real implementation, this would send to Firestore via REST API
        # For now, we'll log and simulate
        $jsonData = $Data | ConvertTo-Json -Depth 3
        Write-Log "Telemetry data: $jsonData"
        
        # TODO: Implement actual Firestore REST API call
        # This would require:
        # 1. Getting Firestore service account credentials (passed from Bootstrap-Agent or from registry)
        # 2. Obtaining access token
        # 3. Formatting Firestore API request
        # 4. Sending via Invoke-RestMethod
        
        return $true
    }
    catch {
        Write-Log "Failed to send telemetry: $_" "ERROR"
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
        
        # For safety in this example, we'll just log what would be done
        Write-Log "Would delete profile: $($Profile.FullName)" "WARN"
        
        # Uncomment the following line for actual deletion (USE WITH EXTREME CAUTION!)
        # Remove-Item -Path $Profile.FullName -Recurse -Force
        
        return $true
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
        
        # Send telemetry about cleanup operation
        if ($TelemetryEnabled) {
            $telemetryData = @{
                deviceId        = $env:COMPUTERNAME
                timestamp       = (Get-Date).ToString("o")
                eventType       = "profile_cleanup"
                profilesFound   = $oldProfiles.Count
                profilesCleaned = $cleanedCount
                minAgeDays      = $MinProfileAgeDays
            }
            Send-Telemetry -Data $telemetryData
        }
    }
    
    Write-Log "=== Core-Ops.ps1 Completed Successfully ==="
    exit 0
}
catch {
    Write-Log "Unhandled error in Core-Ops.ps1: $_" "ERROR"
    
    # Send error telemetry
    if ($TelemetryEnabled) {
        $errorTelemetry = @{
            deviceId     = $env:COMPUTERNAME
            timestamp    = (Get-Date).ToString("o")
            eventType    = "coreops_error"
            errorMessage = $_.Exception.Message
        }
        Send-Telemetry -Data $errorTelemetry | Out-Null
    }
    
    exit 1
}
#endregion
