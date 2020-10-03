$ErrorActionPreference = "Stop"

# Switch network connection to private mode
# Required for WinRM firewall rules
$net_profile = Get-NetConnectionProfile
Set-NetConnectionProfile -Name $net_profile.Name -NetworkCategory Private

# Enable WinRM service
winrm quickconfig -quiet
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="2048"}'
Restart-Service -Name WinRM

netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in localport=5985 protocol=TCP action=allow
netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow

# Reset auto logon count
# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-autologon-logoncount#logoncount-known-issue
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoLogonCount -Value 999

# Change some standard windows explorer settings that suck
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key -Name Hidden -Value 1
Set-ItemProperty $key -Name HideFileExt -Value 0
Set-ItemProperty $key -Name ShowSuperHidden -Value 1

# Reboot of explorer needed for these to take effect
Stop-Process -processname explorer
Start-Process -processname explorer

# Set password to never expire (Using wmic since the latest version of powershell is the only one that works with Set-LocalUser
wmic useraccount WHERE "Name='$Env:Username'" SET PasswordExpires=false

# Set the execution policy of the powershell prompt
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

# Room for further changes here. These should be in the interests of creating templates which are going to be customized by Ansible, not specific actions
$registryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon"

$Name = "DefaultUserName"
$NameValue = "vagrant"
$Password = "DefaultPassword"
$PasswordValue = "vagrant"
$AutoName = "AutoAdminLogon"
New-ItemProperty -Path $registryPath -Name $Name -Value $NameValue -PropertyType "String" -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $Password -Value $PasswordValue -PropertyType "String" -Force | Out-Null
New-ItemProperty -Path $registryPath -Name $AutoName -Value "1" -PropertyType "String" -Force | Out-Null
