###########################################
#
# CommandoVM Installation Script
#
# To execute this script:
# 1) Open powershell window as administrator
# 2) Allow script execution by running command "Set-ExecutionPolicy Unrestricted"
# 3) Unblock the install script by running "Unblock-File .\install.ps1"
# 4) Execute the script by running ".\install.ps1"
#
###########################################
param (
  [string]$password = "",  
  [string]$profile_file = $null, 
  [bool]$nochecks = $false
)


function Set-EnvironmentVariableWrap([string] $key, [string] $value)
{
<#
.SYNOPSIS
	Set the environment variable for all process, user and system wide scopes
.OUTPUTS
	True on success | False on error
#>
  try {
	  [Environment]::SetEnvironmentVariable($key, $value)
	  [Environment]::SetEnvironmentVariable($key, $value, 1)
	  [Environment]::SetEnvironmentVariable($key, $value, 2)
	
	  $rc = $true
	} catch {
		$rc = $false
	}
	$rc
}


function ConvertFrom-Json([object] $item) {
<#
.SYNOPSIS
  Convert a JSON string into a hash table

.DESCRIPTION
  Convert a JSON string into a hash table, without any validation

.OUTPUTS
  [hashtable] or $null
#>
  Add-Type -Assembly system.web.extensions
  $ps_js = New-Object system.web.script.serialization.javascriptSerializer

  try {
    $result = $ps_js.DeserializeObject($item)
  } catch {
    $result = $null
  }
  
  # Cast dictionary to hashtable
  [hashtable] $result
}


function ConvertTo-Json([object] $data) {
<#
.SYNOPSIS
  Convert a hashtable to a JSON string

.DESCRIPTION
  Convert a hashtable to a JSON string, without any validation

.OUTPUTS
  [string] or $null
#>
  Add-Type -Assembly system.web.extensions
  $ps_js = New-Object system.web.script.serialization.javascriptSerializer

  #The comma operator is the array construction operator in PowerShell
  try {
    $result = $ps_js.Serialize($data)
  } catch {
    $result = $null
  }
  
  $result
}


function Import-JsonFile {
<#
.DESCRIPTION
  Load a hashtable from a JSON file
  
.OUTPUTS
  [hashtable] or $null
#>
  param([string] $path)
  try {
    $json = Get-Content $path
    $result = ConvertFrom-Json $json
  } catch {
    $result = $null
  }
  
  $result
}


function Make-InstallerPackage($PackageName, $TemplateDir, $packages) {
	<#
	.SYNOPSIS
	Make a new installer package

	.DESCRIPTION
	Make a new installer package named installer. This package uses the custom packages.json file specified by the user.
	User can then call "Install-BoxStarterPackage installer" using the local repo.
	#>

	$PackageDir = Join-Path $BoxStarter.LocalRepo $PackageName
	if (Test-Path $PackageDir) {
		Remove-Item -Recurse -Force $PackageDir
	}

	$Tmp = [System.IO.Path]::GetTempFileName()
	Write-Host -ForegroundColor Green "packages file is" + $tmp
	ConvertTo-Json @{"packages" = $packages} | Out-File -FilePath $Tmp
	
  if ([System.IO.Path]::IsPathRooted($TemplateDir)) {
    $ToolsDir = Join-Path $TemplateDir "tools"
  } else {
	  $Here = Get-Location
	  $ToolsDir = Join-Path (Join-Path $Here $TemplateDir) "tools"
  }
  $Dest = Join-Path $ToolsDir "packages.json"

	Move-Item -Force -Path $Tmp -Destination $Dest
	New-BoxstarterPackage -Name $PackageName -Description "My Own Instalelr" -Path $ToolsDir
}

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
  

  # Try to install BoxStarter as is first, then fall back to be over trusing only if this step fails.
  try {
		iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
		return $true
	} catch {
	}
   
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
  Write-Host "[+] Installing Boxstarter"
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
function Wait-ForInstall ($seconds) {
  $doneDT = (Get-Date).AddSeconds($seconds)
  while($doneDT -gt (Get-Date)) {
      $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
      $percent = ($seconds - $secondsLeft) / $seconds * 100
      Write-Progress -Activity "Please read install notes on console below" -Status "Beginning install in..." -SecondsRemaining $secondsLeft -PercentComplete $percent
      [System.Threading.Thread]::Sleep(500)
  }
  Write-Progress -Activity "Waiting" -Status "Beginning install..." -SecondsRemaining 0 -Completed
}

Write-Host "`n"
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
Write-Host "|                                 Version 2021.2                             |" -ForegroundColor Red 
Write-Host "|                             commandovm@fireeye.com                         |" -ForegroundColor Red 
Write-Host "|____________________________________________________________________________|" -ForegroundColor Red 
Write-Host "|                                                                            |" -ForegroundColor Red 
Write-Host "|                                   Created by                               |" -ForegroundColor Red 
Write-Host "|                            Jake Barteaux @day1player                       |" -ForegroundColor Red 
Write-Host "|                               Proactive Services                           |" -ForegroundColor Red 
Write-Host "|                         Blaine Stancill @MalwareMechanic                   |" -ForegroundColor Red 
Write-Host "|                                   Nhan Huynh                               |" -ForegroundColor Red 
Write-Host "|                    FireEye Labs Advanced Reverse Engineering               |" -ForegroundColor Red 
Write-Host "|____________________________________________________________________________|" -ForegroundColor Red 
Write-Host ""
  
if ([string]::IsNullOrEmpty($profile_file)) {
  Write-Host "[+] No custom profile is provided..."
  $profile = $null
} else {
  Write-Host "[+] Using the following profile $profile_file"
  $profile = Import-JsonFile $profile_file
  if ($profile -eq $null) {
    Write-Error "Invaild configuration! Exiting..."
    exit 1
  }
  # Confirmation message
  Write-Warning "[+] You are using a custom profile and list of packages,"
  Write-Warning "[+] You will NOT receive new tools automatically when running choco update."

  if ($nochecks -eq $false) {
    Write-Host "[-] Do you want to continue? Y/N " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -ne "Y") {
      Write-Host "[*] Exiting..." -ForegroundColor Red
      exit
    }
  }
  Write-Host "`tContinuing..." -ForegroundColor Green
}


# Check to make sure script is run as administrator
Write-Host "[+] Checking if script is running as administrator.."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "`t[ERR] Please run this script as administrator`n" -ForegroundColor Red
  Write-Host "`n`t`tthis is not the way`n" -ForegroundColor Red
  Read-Host  "Press any key to continue"
  exit
} else {
  Start-Sleep -Milliseconds 500
  Write-Host "`tthis is the way" -ForegroundColor Cyan
  Start-Sleep -Milliseconds 500
}

if ($nochecks -eq $true){
  $defender = Get-Service -Name WinDefend
  if ($defender.Status -eq "Running"){
    Write-Host "[!] Windows Defender is running! ctrl+c to stop script..." -ForegroundColor Yellow
    Start-Sleep -Milliseconds 5000
    Write-Host "[i] Continuing..."
  }
}

if ($nochecks -eq $false) {
  
  # Check to make sure Tamper Protection is off
  # This setting is not able to be changed via command line or via scripts
  Write-Host "[+] Checking to make sure Windows Defender Tamper Protection is disabled"
  if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection") {
    if ($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection").TamperProtection -ne 0){
    Write-Host "[!] Please disable Windows Defender Tamper Protection and retry install." -ForegroundColor Red
    Write-Host "`t[+] Hint: https://www.tenforums.com/tutorials/123792-turn-off-tamper-protection-windows-defender-antivirus.html" -ForegroundColor Yellow
    Write-Host "[-] Do you need to change this setting? Y/N " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -eq "Y") {
      Write-Host "[*] Exiting..." -ForegroundColor Red
      exit
    }
      Write-Host "`tContinuing..." -ForegroundColor Green
    }
  } else {
    Write-Host "`tTamper Protection is off, looks good." -ForegroundColor Green
  }
  
  # Check to make sure Defender is disabled
  Write-Host "[+] Checking if Windows Defender service is running.."
  $defender = Get-Service -Name WinDefend
  if ($defender.Status -eq "Running"){
    Write-Host "[ERR] Please disable Windows Defender through Group Policy" -ForegroundColor Red
    Write-Host "`t[+] Hint: https://stackoverflow.com/questions/62174426/how-to-permanently-disable-windows-defender-real-time-protection-with-gpo" -ForegroundColor Yellow
    Write-Host "[-] Do you need to change this setting? Y/N " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -eq "Y") {
      Write-Host "[*] Exiting..." -ForegroundColor Red
      exit
    }
  }else {
      Start-Sleep -Milliseconds 500
      Write-Host "`tLooks good" -ForegroundColor Cyan
      Start-Sleep -Milliseconds 500
  }
  # Check to make sure host is supported
  Write-Host "[+] Checking to make sure Operating System is compatible"
  if ((Get-WmiObject -class Win32_OperatingSystem).Version -eq "6.1.7601"){
    Write-Host "Windows 7 is no longer supported. Do you want to continue install? Y/N" -ForegroundColor Yellow
    $response = Read-Host
    if ($response -ne "Y"){
      exit
    }
  }
  
  ## Windows 10 Versions/Build Numbers
  # https://github.com/Disassembler0/Win10-Initial-Setup-Script
  # 21H1                        19043
  # 20H2                        19042
  # 2004 (TBD)                  19041
  # 1909 (November 2019 Update)	18363
  # 1903 (May 2019 Update)    	18362
  # 1809 (October 2018 Update)	17763
  # 1803 (April 2018 Update)   	17134


  $osversion = (Get-WmiObject -class Win32_OperatingSystem).BuildNumber
  $valid_versions = @(18363, 18361, 17763, 17134, 19041, 19042, 19043)
  if ($osversion -notin $valid_versions) {
    Write-Host "`t[ERR] Windows version $osversion is not has not been tested, please use Windows 10 version 1803, 1809, 1903, 1909, 2004, 20H2, or 21H1." -ForegroundColor Yellow
    Write-Host "[-] Do you still wish to proceed? Y/N " -ForegroundColor Yellow -NoNewline
    $response = Read-Host 
    if ($response -ne "Y"){
      exit
    }
  } else {
    Write-Host "`tWindows build $osversion supported." -ForegroundColor Green
  }

  #Check to make sure host has enough disk space
  Write-Host "[+] Checking if host has enough disk space"
  $disk = Get-PSDrive C
  Start-Sleep -Seconds 1
  if (-Not (($disk.used + $disk.free)/1GB -gt 58.8)){
    Write-Host "`t[ERR] This install requires a minimum 60 GB hard drive, please increase hard drive space to continue`n" -ForegroundColor Red
    Read-Host "Press any key to continue"
    exit
  } else {
    Write-Host "`t> 60 GB hard drive. looks good" -ForegroundColor Green
  }

  # Prompt user to remind them to take a snapshot
  Write-Host "[-] Do you need to take a snapshot before continuing? Y/N " -ForegroundColor Yellow -NoNewline
  $response = Read-Host
  if ($response -ne "N") {
    Write-Host "[+] Exiting..." -ForegroundColor Red
    exit
  }
  Write-Host "`tContinuing..." -ForegroundColor Green
}

# Get user credentials for autologin during reboots
Write-Host "[+] Getting user credentials ..."
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
if ([string]::IsNullOrEmpty($password)) {
	$cred=Get-Credential $env:username
} else {
	$spasswd=ConvertTo-SecureString -String $password -AsPlainText -Force
	$cred=New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $env:username, $spasswd
}

if ($nochecks -eq $false){
  Write-Host @"

[!] INSTALL NOTES - PLEASE READ CAREFULLY [!]

- This install is not 100% unattended. Please monitor the install for possible failures. If install
fails you may restart the install by re-running the install script with the following command:

      .\install.ps1 -nochecks 1 [<password>]
                   OR
      .\install.ps1 -nochecks 1 -profile_file .\Profiles\<profile>.json [<password>]

- Please be familiar with these two issues:
https://github.com/fireeye/commando-vm/issues/123
https://github.com/fireeye/commando-vm/issues/122

- Install is not complete until the desktop is cleaned, the readme is placed on the desktop, and the
desktop background is set with the Commando VM logo. For details see 
https://github.com/fireeye/commando-vm/issues/139

- You can check what packages failed install by listing the C:\ProgramData\chocolatey\lib-bad 
directory. Failed packages are stored by folder name. You can attempt manual install with the 
following command:

      cinst -y <package name>


- For any issues please submit to GitHub, find @day1player in the BloodHound Slack, or reach 
out to commandovm@fireeye.com

[!] Please copy these notes for reference [!]
"@ -ForegroundColor Red -BackgroundColor White
  Wait-ForInstall -seconds 60
}

Write-Host "`n[+] Beginning Install...`n" -ForegroundColor Green

Write-Host "[+] Installing Boxstarter"
$rc = installBoxStarter
if ( -Not $rc ) {
	Write-Host "[ERR] Failed to install BoxStarter"
	Read-Host  "      Press ANY key to continue..."
	exit 1
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
iex "refreshenv"
iex "choco install -y common.fireeye"
iex "refreshenv"

if ($profile -eq $null) {
  # Default install
  Write-Host "[+] Performing normal installation..."
  if (-Not (Set-EnvironmentVariableWrap "FEVM_PROFILE" "Commando_Default")) {
    Write-Warning "Failed to set environment variable FEVM_PROFILE"
  }
  choco upgrade -y common.fireeye
  if ([System.Environment]::OSVersion.Version.Major -eq 6) {
    Install-BoxstarterPackage -PackageName commandovm.win7.installer.fireeye -Credential $cred
    Install-BoxStarterPackage -PackageName commandovm.win7.config.fireeye  -Credential $cred
  } elseif ([System.Environment]::OSVersion.Version.Major -eq 10) {    
    choco config set cacheLocation ${Env:TEMP}
    iex "choco upgrade -y commandovm.win10.preconfig.fireeye"
    Install-BoxstarterPackage -PackageName commandovm.win10.installer.fireeye -Credential $cred
    Install-BoxStarterPackage -PackageName commandovm.win10.config.fireeye  -Credential $cred
  }
  exit 0
} 

# The necessary basic environment variables
$EnvVars = @(
  "VM_COMMON_DIR",
  "TOOL_LIST_DIR",
  "TOOL_LIST_SHORTCUT",
  "RAW_TOOLS_DIR",
  "FEVM_PROFILE"
  )

foreach ($envVar in $EnvVars) {
  try {
		$value = [Environment]::ExpandEnvironmentVariables($profile.env.($envVar))
		if (-Not (Set-EnvironmentVariableWrap $envVar $value)) {
			Write-Warning "[ - ] Failed to set environment variable $envVar"
		}
  } catch {}
}

$PackageName = "MyInstaller"
$TemplateDir = $profile.env.TEMPLATE_DIR
$Packages = $profile.packages
Make-InstallerPackage $PackageName $TemplateDir $Packages
Invoke-BoxStarterBuild $PackageName
if ([System.Environment]::OSVersion.Version.Major -eq 6) {
  Install-BoxStarterPackage -PackageName $PackageName -Credential $cred
  Install-BoxStarterPackage -PackageName commandovm.win7.config.fireeye  -Credential $cred
} elseif ([System.Environment]::OSVersion.Version.Major -eq 10) {
  iex "choco upgrade -y commandovm.win10.preconfig.fireeye"
  Install-BoxStarterPackage -PackageName $PackageName -Credential $cred
  Install-BoxStarterPackage -PackageName commandovm.win10.config.fireeye  -Credential $cred
}
exit 0
