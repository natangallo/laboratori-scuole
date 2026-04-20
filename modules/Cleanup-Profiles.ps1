param(
    [hashtable]$Context
)

# 1. Configurazione Iniziale
$LogPath = $Context.LogPath
$MinProfileAgeDays = 1
if ($Context.minProfileAgeDays) { $MinProfileAgeDays = $Context.minProfileAgeDays }

function Write-ModuleLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Mod:Cleanup] $Message"
    Add-Content -Path (Join-Path $LogPath "Governance.log") -Value $logEntry
    Write-Host $logEntry
}

$GC_ExcludeList = @("Administrator", "ladmin", "Public", "Default", "Default User", "All Users")
$GC_ExcludePatterns = @("doc.*", "admin.*", "supervisore.*")

function Get-StaleProfiles {
    param([int]$MinAgeDays)
    try {
        $cutoffDate = (Get-Date).AddDays(-$MinAgeDays)
        $candidates = Get-CimInstance -Class Win32_UserProfile | Where-Object {
            $pName = $_.LocalPath.Split('\')[-1]
            $_.Special -eq $false -and
            $pName -notin $GC_ExcludeList -and
            (-not ($GC_ExcludePatterns | Where-Object { $pName -like $_ })) -and
            $_.LastUseTime -ne $null -and
            $_.LastUseTime -lt $cutoffDate -and
            $_.Loaded -eq $false
        }
        return $candidates
    } catch {
        Write-ModuleLog "Error querying profiles: $_" "ERROR"
        return @()
    }
}

function Cleanup-Profile {
    param([CimInstance]$ProfileInstance)
    try {
        $profileName = $ProfileInstance.LocalPath.Split('\')[-1]
        if ($ProfileInstance.Loaded) { return $false }
        Remove-CimInstance -InputObject $ProfileInstance -ErrorAction Stop
        Write-ModuleLog "Profile $profileName removed (CIM Atomic)." 
        return $true
    } catch {
        Write-ModuleLog "Failed to remove $profileName : $_" "ERROR"
        return $false
    }
}
#endregion

#region Execution
Write-ModuleLog "Starting Cleanup Module..."
$staleProfiles = Get-StaleProfiles -MinAgeDays $MinProfileAgeDays
$cleanedCount = 0

if ($staleProfiles.Count -eq 0) {
    Write-ModuleLog "No stale profiles found."
} else {
    foreach ($p in $staleProfiles) {
        if (Cleanup-Profile -ProfileInstance $p) { $cleanedCount++ }
        Start-Sleep -Milliseconds 200
    }
    Write-ModuleLog "Cleanup finished. $cleanedCount profiles removed."
}

# Return ResultObject to Launcher
return [PSCustomObject]@{
    Module  = "profile-cleanup"
    Success = $true
    Status  = "Completed"
    Details = @{
        profilesFound   = [int]$staleProfiles.Count
        profilesCleaned = [int]$cleanedCount
    }
}
#endregion
