<#
.SYNOPSIS
    Rekordata Windows Bootstrap Agent (Thin Client)
.DESCRIPTION
    v2.2.9 - Modular Architecture (PS 5.1 Native Compatibility).
    This static script is responsible for:
    - Provisioning: Creating the local hierarchy and scheduling the task.
    - Launching: Downloading the Launcher.ps1 in-memory and executing it.
.NOTES
    Author: Rekordata Team
    Version: 2.2.9
#>

param(
    [switch]$Provision,
    [switch]$Force
)

# Elevation Check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "FATAL: This script must be run as Administrator." -ForegroundColor Red
    return
}

# Configuration
$BaseDir = "C:\ProgramData\Rekordata"
$LogPath = Join-Path $BaseDir "Logs"
$LauncherUrl = "https://raw.githubusercontent.com/natangallo/laboratori-scuole/main/Launcher.ps1"
$RegistryPath = "HKLM:\SOFTWARE\Policies\Rekordata\Governance"

# Helper for Logging (Minimal for Bootstrap)
function Write-BootstrapLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [Bootstrap] $Message"
    if (-not (Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
    Add-Content -Path (Join-Path $LogPath "Governance.log") -Value $logEntry
    Write-Host $logEntry
}

# --- Stage 1: Provisioning ---
if ($Provision) {
    try {
        Write-BootstrapLog "Starting Provisioning Stage..."
        
        # 1. Environment Check
        if (-not (Test-Path $BaseDir)) { 
            New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null 
            Write-BootstrapLog "Created $BaseDir"
        }

        # 2. Self-copy with Dynamic Discovery
        $sourceScript = $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($sourceScript) -or -not (Test-Path $sourceScript)) {
            $sourceScript = Join-Path (Get-Location) "Bootstrap-Agent.ps1"
        }
        
        $targetScript = Join-Path $BaseDir "Bootstrap-Agent.ps1"
        if ((Test-Path $sourceScript) -and ($sourceScript -ne $targetScript)) {
            Write-BootstrapLog "Copying agent to $targetScript..."
            Copy-Item -Path $sourceScript -Destination $targetScript -Force -ErrorAction Stop
        }

        # 3. Scheduled Task Registration
        $taskName = "Rekordata-Bootstrap"
        $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if (-not $taskExists -or $Force) {
            Write-BootstrapLog "Registering/Updating Scheduled Task..."
            
            # Action to execute the local copy
            $action = New-ScheduledTaskAction -Execute "powershell.exe" `
                -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$targetScript`""
            
            # Triggers: Need separate calls for AtLogon and AtStartup
            $triggers = @(
                (New-ScheduledTaskTrigger -AtLogon),
                (New-ScheduledTaskTrigger -AtStartup)
            )
            
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
            
            # Basic settings for reliability
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            
            # Force registration with ErrorAction Stop
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force -ErrorAction Stop | Out-Null
            
            Write-BootstrapLog "Task registered successfully."
        }
        
        Write-BootstrapLog "Provisioning Completed."
        exit 0
    }
    catch {
        Write-BootstrapLog "Provisioning FAILED: $_" "ERROR"
        exit 1
    }
}

# --- Stage 2: Launch Orchestrator (In-Memory) ---
try {
    Write-BootstrapLog "=== Bootstrap v2.2.9 Active ==="
    
    # 1. Download Launcher in-memory
    Write-BootstrapLog "Fetching Launcher from $LauncherUrl..."
    
    # Cache busting to avoid GitHub Raw cache (aggressive headers + nano-timestamp)
    $headers = @{
        "Cache-Control" = "no-cache"
        "Pragma"        = "no-cache"
    }
    $cacheBuster = [DateTime]::UtcNow.Ticks
    $urlWithCache = "$($LauncherUrl.Trim())?nocache=$cacheBuster"
    
    $launcherCode = Invoke-RestMethod -Uri $urlWithCache -Headers $headers -ErrorAction Stop
    
    if (-not $launcherCode) { throw "Launcher source is empty." }

    # 2. Execution in-memory
    Write-BootstrapLog "Executing Launcher in-memory..."
    $scriptBlock = [scriptblock]::Create($launcherCode)
    
    # Execute the scriptblock
    & $scriptBlock
    
    Write-BootstrapLog "=== Bootstrap Session Ended ==="
}
catch {
    Write-BootstrapLog "Bootstrap Execution Error: $_" "ERROR"
    exit 1
}
