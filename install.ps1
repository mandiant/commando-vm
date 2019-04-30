###########################################
#
# CommandoVM Installation Script
#
# To execute this script:
# 1) Open powershell window as administrator
# 2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
# 3) Execute the script by running ".\install.ps1"
#
###########################################
param (
  [string]$password = "",
  [bool]$nochecks = $false
)
function installBoxStarter()
{
  <#
  .SYNOPSIS
  Install BoxStarter on the current system  
  .DESCRIPTION
  Install BoxStarter on the current system. Returns $true or $false to indicate success or failure. On
  fresh windows 7 systems, some root certificates are not installed and updated properly. Therefore,
  this funciton also temporarily trust all certificates before installing BoxStarter.  
  #>  
  # https://stackoverflow.com/questions/11696944/powershell-v3-invoke-webrequest-https-error
  # Allows current PowerShell session to trust all certificates
  # Also a good find: https://www.briantist.com/errors/could-not-establish-trust-relationship-for-the-ssltls-secure-channel/
  try {
  Add-Type @"
  using System.Net;
  using System.Security.Cryptography.X509Certificates;
  public class TrustAllCertsPolicy : ICertificatePolicy {
  	public bool CheckValidationResult(
  		ServicePoint srvPoint, X509Certificate certificate,
  		WebRequest request, int certificateProblem) {
  		return true;
  	}
  }
"@
  } catch {
    Write-Debug "Failed to add new type"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
  } catch {
  	Write-Debug "Failed to find SSL type...1"
  }  
  try {
  	$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
  } catch {
  	Write-Debug "Failed to find SSL type...2"
  }  
  $prevSecProtocol = [System.Net.ServicePointManager]::SecurityProtocol
  $prevCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy  
  Write-Host "[ * ] Installing Boxstarter"
  # Become overly trusting
  [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy  
  # download and instal boxstarter
  iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force  
  # Restore previous trust settings for this PowerShell session
  # Note: SSL certs trusted from installing BoxStarter above will be trusted for the remaining PS session
  [System.Net.ServicePointManager]::SecurityProtocol = $prevSecProtocol
  [System.Net.ServicePointManager]::CertificatePolicy = $prevCertPolicy
  return $true
}
Write-Host "[+] Beginning install..."
Write-Host " ____________________________________________________________________________ " -ForegroundColor Red 
Write-Host "|                                                                            |" -ForegroundColor Red 
Write-Host "|    "  -ForegroundColor Red -NoNewline; Write-Host "                  " -ForegroundColor Green -NoNewline; Write-Host "                                                      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host "_________                                           .___      " -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host "\_   ___ \  ____   _____   _____ _____    ____    __| _/____  " -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host "/    \  \/ /  _ \ /     \ /     \\__  \  /    \  / __ |/  _ \ " -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host "\     \___(  <_> )  Y Y  \  Y Y  \/ __ \|   |  \/ /_/ (  <_> )" -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host " \______  /\____/|__|_|  /__|_|  (____  /___|  /\____ |\____/ " -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|        "  -ForegroundColor Red -NoNewline; Write-Host "        \/             \/      \/     \/     \/      \/       " -ForegroundColor Green -NoNewline; Write-Host "      |" -ForegroundColor Red 
Write-Host "|                       C O M P L E T E  M A N D I A N T                     |" -ForegroundColor Red 
Write-Host "|                            O F F E N S I V E   V M                         |" -ForegroundColor Red 
Write-Host "|                                                                            |" -ForegroundColor Red 
Write-Host "|                                  Version 1.1                               |" -ForegroundColor Red 
Write-Host "|____________________________________________________________________________|" -ForegroundColor Red 
Write-Host "|                                                                            |" -ForegroundColor Red 
Write-Host "|                                  Developed by                              |" -ForegroundColor Red 
Write-Host "|                                 Jake  Barteaux                             |" -ForegroundColor Red 
Write-Host "|                               Proactive Services                           |" -ForegroundColor Red 
Write-Host "|                                 Blaine Stancill                            |" -ForegroundColor Red 
Write-Host "|                                   Nhan Huynh                               |" -ForegroundColor Red 
Write-Host "|                    FireEye Labs Advanced Reverse Engineering               |" -ForegroundColor Red 
Write-Host "|____________________________________________________________________________|" -ForegroundColor Red 
Write-Host ""


# Check to make sure script is run as administrator
Write-Host "[+] Checking if script is running as administrator.."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "`t[ERR] Please run this script as administrator`n" -ForegroundColor Red
  Read-Host  "Press any key to continue"
  exit
}
else {
  Start-Sleep -Milliseconds 500
  Write-Host "`tphenomenal " -ForegroundColor Magenta -NoNewLine
  Start-Sleep -Milliseconds 500
  Write-Host "cosmic " -ForegroundColor Cyan -NoNewLine
  Start-Sleep -Milliseconds 500
  Write-Host "powers " -ForegroundColor Green
  Start-Sleep -Milliseconds 500
}

if ($nochecks -eq $false) {
  
  # Check to make sure host is supported
  Write-Host "[+] Checking to make sure Operating System is compatible"
  if (-Not (((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601") -or ([System.Environment]::OSVersion.Version.Major -eq 10))){
    Write-Host "`t[ERR] $((Get-WmiObject -class Win32_OperatingSystem).Caption) is not supported, please use Windows 7 Service Pack 1 or Windows 10" -ForegroundColor Red
    exit 
  }
  else
  {
    Write-Host "`t$((Get-WmiObject -class Win32_OperatingSystem).Caption) supported" -ForegroundColor Green
  }

  # Check to make sure host has been updated
  Write-Host "[+] Checking if host has been configured with updates"
  if (-Not (get-hotfix | where { (Get-Date($_.InstalledOn)) -gt (get-date).adddays(-30) })) {
    Write-Host "`t[ERR] This machine has not been updated in the last 30 days, please run Windows Updates to continue`n" -ForegroundColor Red
    Read-Host  "Press any key to continue"
    exit
  }
  else
  {
	  Write-Host "`tupdates appear to be in order" -ForegroundColor Green
  }

  #Check to make sure host has enough disk space
  Write-Host "[+] Checking if host has enough disk space"
  $disk = Get-PSDrive C
  Start-Sleep -Seconds 1
  if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)){
    Write-Host "`t[ERR] This install requires a minimum 60 GB hard drive, please increase hard drive space to continue`n" -ForegroundColor Red
    Read-Host "Press any key to continue"
    exit
  }
  else
  {
    Write-Host "`t> 60 GB hard drive. looks good" -ForegroundColor Green
  }

  # Prompt user to remind them to take a snapshot
  Write-Host "[-] Do you need to take a snapshot before continuing? Y/N " -ForegroundColor Yellow -NoNewline
  $response = Read-Host
  if ($response -ne "N") {
    Write-Host "[*] Exiting..." -ForegroundColor Red
    exit
  }
  Write-Host "`tContinuing..." -ForegroundColor Green
}

# Get user credentials for autologin during reboots
Write-Host "[ * ] Getting user credentials ..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True

if ([string]::IsNullOrEmpty($password)) {
	$cred=Get-Credential $env:username
} else {
	$spasswd=ConvertTo-SecureString -String $password -AsPlainText -Force
	$cred=New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $env:username, $spasswd
}
# TO DO - Verify credentials before continuing

# Install Boxstarter
Write-Host "[ * ] Installing Boxstarter"
try {
  iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
} catch {
  $rc = installBoxStarter
  if (-Not $rc) {
  	Write-Host "[ERR] Failed to install BoxStarter"
  	Read-Host  "      Press ANY key to continue..."
  	exit
  }
}

# Boxstarter options
$Boxstarter.RebootOk = $true    # Allow reboots?
$Boxstarter.NoPassword = $false # Is this a machine with no login password?
$Boxstarter.AutoLogin = $true   # Save my password securely and auto-login after a reboot
Set-BoxstarterConfig -NugetSources "https://www.myget.org/F/fireeye/api/v2;https://chocolatey.org/api/v2"

# Needed for many applications
# Set up the correct feed
$fireeyeFeed = "https://www.myget.org/F/fireeye/api/v2"
iex "choco sources add -n=fireeye -s $fireeyeFeed --priority 1"
iex "choco upgrade -y vcredist-all.flare"
iex "cinst -y powershell"

if ([System.Environment]::OSVersion.Version.Major -eq 6) {
  Install-BoxstarterPackage -PackageName commandovm.win7.installer.fireeye -Credential $cred
} elseif ([System.Environment]::OSVersion.Version.Major -eq 10) {
  choco config set cacheLocation ${Env:TEMP}
  iex "choco upgrade -y commandovm.win10.preconfig.fireeye"
  Install-BoxstarterPackage -PackageName commandovm.win10.installer.fireeye -Credential $cred
} else {
  Write-Host "`t[ERR] This install requires Windows 7 SP1 or Windows 10`n" -ForegroundColor Red
}
