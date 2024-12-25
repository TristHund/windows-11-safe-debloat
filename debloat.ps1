# Run this script as Administrator
# Version: 1.0
# Last Updated: 2024-12-25
# This script safely removes bloatware while preserving system security and functionality

# Verify running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
    exit 1
}

# Verify Windows 11
$osInfo = Get-WmiObject -Class Win32_OperatingSystem
if (-not ($osInfo.Caption -like "*Windows 11*")) {
    Write-Error "This script is designed for Windows 11 only. Detected OS: $($osInfo.Caption)"
    exit 1
}

# Create log file
$logPath = "$env:USERPROFILE\Desktop\DebloatLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Start-Transcript -Path $logPath
# Create a restore point first
Checkpoint-Computer -Description "Before Safe Windows Debloating" -RestorePointType "MODIFY_SETTINGS"

Write-Host "Creating System Restore Point..."

# Function to safely remove AppX packages
function Remove-BloatwarePackage {
    param (
        [string]$PackageName
    )
    Write-Host "Removing $PackageName..."
    Get-AppxPackage $PackageName | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $PackageName | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

# List of safe-to-remove packages
$bloatwareApps = @(
    "Microsoft.BingNews"
    "Microsoft.BingWeather"
    "Microsoft.GamingApp"      # Xbox
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.People"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.ToDo"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"  # Mail and Calendar
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"      # Media Player
    "Microsoft.Windows.QuickAssist"
    "Microsoft.Clipchamp"
)

# Remove AppX packages
foreach ($app in $bloatwareApps) {
    Remove-BloatwarePackage -PackageName $app
}

# Safe removal of optional features
$optionalFeatures = @(
    "Internet-Explorer-Optional-amd64"
    "MathRecognizer"          # Tablet PC Math
)

foreach ($feature in $optionalFeatures) {
    Write-Host "Removing Optional Feature: $feature"
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}

# Disable unnecessary services while keeping essential ones
$servicesToDisable = @(
    "MapsBroker"              # Downloaded Maps Manager
    "RetailDemo"              # Retail Demo Service
    "XblGameSave"             # Xbox Live Game Save
    "XboxNetApiSvc"           # Xbox Live Networking Service
)

foreach ($service in $servicesToDisable) {
    Set-Service -Name $service -StartupType Disabled
    Stop-Service -Name $service -Force
}

# Registry modifications to reduce telemetry while maintaining security
Write-Host "Configuring privacy settings..."
$registrySettings = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" = @{
        "DisableWindowsConsumerFeatures" = 1
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoNewAppAlert" = 1
    }
}

foreach ($path in $registrySettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    $settings = $registrySettings[$path]
    foreach ($name in $settings.Keys) {
        Set-ItemProperty -Path $path -Name $name -Value $settings[$name]
    }
}

# Disable sponsored apps and suggestions
Write-Host "Disabling sponsored content..."
$contentDeliverySettings = @{
    "ContentDeliveryAllowed" = 0
    "OemPreInstalledAppsEnabled" = 0
    "PreInstalledAppsEnabled" = 0
    "SilentInstalledAppsEnabled" = 0
    "SystemPaneSuggestionsEnabled" = 0
}

$cdmPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($setting in $contentDeliverySettings.Keys) {
    Set-ItemProperty -Path $cdmPath -Name $setting -Value $contentDeliverySettings[$setting]
}

# Keep Windows Update enabled but configure for more control
Write-Host "Configuring Windows Update for more control..."
$wuSettings = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
        "NoAutoUpdate" = 0
        "AUOptions" = 2  # Notify before download and install
    }
}

foreach ($path in $wuSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    $settings = $wuSettings[$path]
    foreach ($name in $settings.Keys) {
        Set-ItemProperty -Path $path -Name $name -Value $settings[$name]
    }
}

# Verify system integrity after changes
Write-Host "Verifying system integrity..."
$systemIntegrityCheck = @(
    @{Name="Windows Defender"; Service="WinDefend"}
    @{Name="Windows Update"; Service="wuauserv"}
    @{Name="Security Center"; Service="wscsvc"}
)

$errorsFound = $false
foreach ($check in $systemIntegrityCheck) {
    $service = Get-Service -Name $check.Service -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne 'Running') {
        Write-Error "Critical service check failed: $($check.Name)"
        $errorsFound = $true
    }
}

if ($errorsFound) {
    Write-Warning "Some system integrity checks failed. Please review the log file at $logPath"
} else {
    Write-Host "System integrity verified successfully." -ForegroundColor Green
}

Write-Host "`nDebloating process completed. Changes made:"
Write-Host "- Removed non-essential Microsoft Store apps"
Write-Host "- Disabled unnecessary services"
Write-Host "- Configured privacy settings"
Write-Host "- Preserved Windows Defender and security features"
Write-Host "- Maintained Windows Update functionality"

Write-Host "`nNext steps:"
Write-Host "1. Review the log file at: $logPath"
Write-Host "2. Restart your computer to apply all changes"
Write-Host "3. After restart, verify Windows Update and Windows Security are functioning"

Stop-Transcript
