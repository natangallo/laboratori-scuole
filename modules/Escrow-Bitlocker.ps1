# Module: Escrow-Bitlocker
# Provides BitLocker activation and Cloud Escrow (Firestore)
# Requirement: Launcher context (AccessToken, ProjectId)

<#
.SYNOPSIS
    Rekordata Windows Governance - BitLocker Module
.DESCRIPTION
    v2.2.6 - Activation & Cloud Escrow with verbose logging.
.NOTES
    Author: Rekordata Team
    Version: 2.2.6
#>

param(
    [hashtable]$Context
)

# 1. Configurazione Iniziale & Validazione
$LogPath = $Context.LogPath
$AccessToken = $Context.AccessToken
$RegistryPath = $Context.RegistryPath
$BitlockerFolderId = $Context.folderId
$BitlockerUsedSpaceOnly = $true

function Write-ModuleLog {
    param([string]$Message, [string]$Level = "INFO")
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Stamp] [$Level] [Mod:BitLocker] $Message"
    if ($LogPath) { Add-Content -Path (Join-Path $LogPath "Governance.log") -Value $Line }
    Write-Host $Line
}

function Get-EncryptionStatus {
    $drive = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq "C:" }
    if ($null -eq $drive) { return "None" }
    
    $statusMap = @{
        0 = "FullyDecrypted"
        1 = "FullyEncrypted"
        2 = "EncryptionInProgress"
        3 = "DecryptionInProgress"
        4 = "EncryptionPaused"
        5 = "DecryptionPaused"
    }
    return $statusMap[[int]$drive.ProtectionStatus]
}

function Get-BitLockerKey {
    $drive = Get-CimInstance -Namespace "root\CIMv2\Security\MicrosoftVolumeEncryption" -ClassName "Win32_EncryptableVolume" | Where-Object { $_.DriveLetter -eq "C:" }
    if ($null -eq $drive) { return $null }
    
    $keyProt = @()
    $drive.GetKeyProtectors(3, [ref]$keyProt) | Out-Null # 3 = NumericalPassword
    
    if ($keyProt.Length -gt 0) {
        $keyId = $keyProt[0]
        $pass = ""
        $drive.GetKeyProtectorNumericalPassword($keyId, [ref]$pass) | Out-Null
        return @{
            ID       = $keyId
            Password = $pass
        }
    }
    return $null
}

function Invoke-BitLockerActivation {
    param([string]$Method = "xts_aes256")
    Write-ModuleLog "Activating BitLocker (Method: $Method)..."
    
    # Try to enable protection with TPM. Capture output for debug.
    $output = manage-bde -on C: -Used -EncryptionMethod $Method -SkipHardwareTest -RecoveryPassword 2>&1
    $success = $LASTEXITCODE -eq 0
    
    # Force a key backup to AD/Local if possible
    $key = Get-BitLockerKey
    if ($key) { manage-bde -protectors -adbackup C: -id $key.ID | Out-Null }
    
    return @{ Success = $success; Output = ($output -join "`n"); StatusNote = "attempted" }
}

function Send-Escrow {
    param([string]$AccessToken, [string]$ProjectId, [string]$KeyId, [string]$Password)
    Write-ModuleLog "Sending Key Escrow to Cloud..."
    
    $Id = $env:COMPUTERNAME
    $Url = "https://firestore.googleapis.com/v1/projects/$ProjectId/databases/(default)/documents/escrow/$Id"
    
    $Payload = @{
        fields = @{
            key_id     = @{ stringValue = $KeyId }
            recovery   = @{ stringValue = $Password }
            created_at = @{ stringValue = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") }
        }
    } | ConvertTo-Json -Depth 10
    
    $Headers = @{ Authorization = "Bearer $AccessToken" }
    
    try {
        Invoke-RestMethod -Uri $Url -Method Patch -Headers $Headers -ContentType "application/json" -Body $Payload | Out-Null
        Write-ModuleLog "Escrow Completed Successfully."
    }
    catch {
        Write-ModuleLog "Escrow Failed: $_" "ERROR"
    }
}

function Get-BitLockerMDMPolicy {
    $fvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
    $result = @{ PolicyPresent = $false; EncryptionMethod = "xts_aes256" }
    if (Test-Path $fvePath) {
        $result.PolicyPresent = $true
        $methodMap = @{ 3 = "aes128"; 4 = "aes256"; 6 = "xts_aes128"; 7 = "xts_aes256" }
        $raw = (Get-ItemProperty -Path $fvePath -ErrorAction SilentlyContinue).EncryptionMethodWithXtsOs
        if ($raw -and $methodMap.ContainsKey([int]$raw)) { $result.EncryptionMethod = $methodMap[[int]$raw] }
    }
    return $result
}

# --- Main Execution ---
Write-ModuleLog "Checking BitLocker Governance..."

$status = Get-EncryptionStatus
Write-ModuleLog "Volume C: Status is '$status'."

# If not protected, activate
if ($status -ne "FullyEncrypted" -and $status -ne "EncryptionInProgress") {
    $mdmPolicy = Get-BitLockerMDMPolicy
    if ($mdmPolicy.PolicyPresent) {
        $activation = Invoke-BitLockerActivation -EncryptionMethod $mdmPolicy.EncryptionMethod
        if (-not $activation.Success) {
            Write-ModuleLog "Activation step failed. Detail: $($activation.Output)" "ERROR"
        }
    } else {
        Write-ModuleLog "No MDM Policy for BitLocker. Skipping activation."
        $activation = @{ Success = $true; StatusNote = "skipped_policy" }
    }
} else {
    $activation = @{ Success = $true; StatusNote = "already_active" }
}

# Always ensure escrow is up to date if we have a key
$key = Get-BitLockerKey
if ($null -ne $key) {
    if ($AccessToken -and $Context.ProjectId) {
        Send-Escrow -AccessToken $AccessToken -ProjectId $Context.ProjectId -KeyId $key.ID -Password $key.Password
    }
    else {
        Write-ModuleLog "Skipping cloud escrow: Missing context." "WARNING"
    }
}
else {
    Write-ModuleLog "No BitLocker numerical password found to escrow." "WARNING"
}
