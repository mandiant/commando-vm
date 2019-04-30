$ErrorActionPreference = 'Continue'
function Set-PinnedApplication { 
  [CmdletBinding()] 
  param( 
  [Parameter(Mandatory=$true)][string]$Action,  
  [Parameter(Mandatory=$true)][string]$FilePath 
  ) 
  if(-not (test-path $FilePath)) {  
    throw "FilePath does not exist."   
  } 
    
  function InvokeVerb { 
    param([string]$FilePath,$verb) 
    $verb = $verb.Replace("&","") 
    $path= split-path $FilePath 
    $shell=new-object -com "Shell.Application"  
    $folder=$shell.Namespace($path)    
    $item = $folder.Parsename((split-path $FilePath -leaf)) 
    $itemVerb = $item.Verbs() | ? {$_.Name.Replace("&","") -eq $verb} 
    if($itemVerb -eq $null){ 
      throw "Verb $verb not found."             
    } else { 
      $itemVerb.DoIt() 
    } 
  }

  function GetVerb { 
    param([int]$verbId) 
    try { 
      $t = [type]"CosmosKey.Util.MuiHelper" 
    } catch { 
      $def = [Text.StringBuilder]"" 
      [void]$def.AppendLine('[DllImport("user32.dll")]') 
      [void]$def.AppendLine('public static extern int LoadString(IntPtr h,uint id, System.Text.StringBuilder sb,int maxBuffer);') 
      [void]$def.AppendLine('[DllImport("kernel32.dll")]') 
      [void]$def.AppendLine('public static extern IntPtr LoadLibrary(string s);') 
      add-type -MemberDefinition $def.ToString() -name MuiHelper -namespace CosmosKey.Util             
    } 
    if($global:CosmosKey_Utils_MuiHelper_Shell32 -eq $null){         
      $global:CosmosKey_Utils_MuiHelper_Shell32 = [CosmosKey.Util.MuiHelper]::LoadLibrary("shell32.dll") 
    } 
    $maxVerbLength=255 
    $verbBuilder = new-object Text.StringBuilder "",$maxVerbLength 
    [void][CosmosKey.Util.MuiHelper]::LoadString($CosmosKey_Utils_MuiHelper_Shell32,$verbId,$verbBuilder,$maxVerbLength) 
    return $verbBuilder.ToString() 
  } 

  $verbs = @{  
    "PintoStartMenu"=5381 
    "UnpinfromStartMenu"=5382 
    "PintoTaskbar"=5386 
    "UnpinfromTaskbar"=5387 
  } 
      
  if($verbs.$Action -eq $null){ 
    Throw "Action $action not supported`nSupported actions are:`n`tPintoStartMenu`n`tUnpinfromStartMenu`n`tPintoTaskbar`n`tUnpinfromTaskbar" 
  } 
  InvokeVerb -FilePath $FilePath -Verb $(GetVerb -VerbId $verbs.$action) 
} 

$packageName = 'commandovm.win7.config.fireeye'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

### Commando Windows 7 Attack VM ###
Write-Host "[+] Beginning host configuration..." -ForegroundColor Green
Write-Host "[+] Disabling LLMNR (No pwning yourself with Responder!)" -ForegroundColor Green


#### Disable LLMNR ####
$registryPath = "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient"
if (-Not (Test-Path $registryPath)) {
  New-Item -path $registryPath -Force | Out-Null
}
New-ItemProperty -Path $registryPath -Name "EnableMulticast" -Value 0 -PropertyType DWORD -Force | Out-Null


#### Disable services ####
Write-Host "[-] Disabling services" -ForegroundColor Green
Set-Service MpsSvc -StartupType Disabled -ErrorAction SilentlyContinue # Windows Firewall
Write-Host "`t[+] Disabled Windows Defender" -ForegroundColor Green

# TODO: move to OpenVPN package
Set-Service OpenVPNService -StartupType Manual -ErrorAction SilentlyContinue 
Set-Service OpenVPNServiceInteractive -StartupType Manual -ErrorAction SilentlyContinue 
Set-Service OpenVPNServiceLegacy -StartupType Manual -ErrorAction SilentlyContinue 
Write-Host "`t[+] Disabled OpenVPN Services" -ForegroundColor Green
Set-Service neo4j -StartupType Manual -ErrorAction SilentlyContinue
Stop-Service -Name neo4j -ErrorAction SilentlyContinue
Write-Host "`t[+] Disabled Neo4j" -ForegroundColor Green
Set-Service OpenSSHd -StartupType Manual -ErrorAction SilentlyContinue
Stop-Service -Name OpenSSHd -ErrorAction SilentlyContinue
Write-Host "`t[+] Disabled OpenSSH Service" -ForegroundColor Green
Start-Sleep -Seconds 2


#### Remove Desktop Shortcuts ####
Write-Host "[+] Cleaning up the Desktop" -ForegroundColor Green
$shortcut_path = "C:\Users\Public\Desktop\Boxstarter Shell.lnk"
Remove-Item $shortcut_path -Force | Out-Null
Start-Sleep -Seconds 2


#### Set file associations ####
Write-Host "[-] Setting file associations..." -ForegroundColor Green
# Zip
$7zip = "${Env:ProgramFiles}\7-Zip\7z.exe"
if (Test-Path $7zip) {
  $7zipfiletype = "7z.exe"
  cmd /c assoc .zip=$7zipfiletype | Out-Null
  cmd /c assoc .7z=$7zipfiletype | Out-Null
  cmd /c assoc .tar=$7zipfiletype | Out-Null
  cmd /c assoc .bz=$7zipfiletype | Out-Null
  cmd /c assoc .gz=$7zipfiletype | Out-Null
  cmd /c assoc .gzip=$7zipfiletype | Out-Null
  cmd /c assoc .bzip=$7zipfiletype | Out-Null
  cmd /c @"
    ftype $7zipfiletype="$7zip" "%1" "%*" > NUL
"@
  New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
  Set-ItemProperty -Path "HKCR:\$7zipfiletype" -Name "(DEFAULT)" -Value "$7zipfiletype file" -Force | Out-Null
  Write-Host "`t[+] 7zip -> .zip" -ForegroundColor Green
}


#### Unpin Items from Taskbar ####
# TODO: more research: https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/8
Write-Host "[+] Unpinning IE and Windows Media Player from Taskbar" -ForegroundColor Green
$unpin_list = @(
  "${Env:ProgramFiles}\Internet Explorer\iexplore.exe",
  "${Env:ProgramFiles(x86)}\Windows Media Player\wmplayer.exe",
  "${Env:WinDir}\explorer.exe"
)
foreach ($to_unpin in $unpin_list) {
  try {
    Set-PinnedApplication -Action UnPinFromTaskBar -FilePath "$to_unpin"
  } catch {}
}
Start-Sleep -Seconds 2


#### Add timestamp to PowerShell prompt ####
$psprompt = @"
function prompt
{
    Write-Host "COMMANDO " -ForegroundColor Green -NoNewLine
    Write-Host `$(get-date) -ForegroundColor Green
    Write-Host  "PS" `$PWD ">" -nonewline -foregroundcolor White
    return " "
}
"@
New-Item -ItemType File -Path $profile -Force | Out-Null
Set-Content -Path $profile -Value $psprompt
# Add timestamp to cmd prompt
# Note: The string below is base64-encoded due to issues properly escaping the '$' character in PowersShell
#   Offending string: "Y21kIC9jICdzZXR4IFBST01QVCBDT01NQU5ETyRTJGQkcyR0JF8kcCQrJGcn"
#   Resolves to: "cmd /c 'setx PROMPT COMMANDO$S$d$s$t$_$p$+$g'"
iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y21kIC9jICdzZXR4IFBST01QVCBDT01NQU5ETyRTJGQkcyR0JF8kcCQrJGcn"))) | Out-Null
Write-Host "`t[+] Timestamps added to cmd prompt and PowerShell" -ForegroundColor Green


#### Pin Items to Taskbar ####
Write-Host "[-] Pinning items to Taskbar" -ForegroundColor Green
$target_file = Join-Path ${Env:WinDir} "explorer.exe"
$shortcut = Join-Path ${Env:UserProfile} "temp\explorer.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -PinToTaskbar
# CMD prompt
Write-Host "`t[+] cmd.exe" -ForegroundColor Green
$target_file = Join-Path ${Env:WinDir} "system32\cmd.exe"
$target_dir = ${Env:UserProfile}
$target_args = '/K "cd ' + ${Env:UserProfile} + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\CMD.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin
# Powershell
Write-Host "`t[+] Powershell" -ForegroundColor Green
$target_file = Join-Path (Join-Path ${Env:WinDir} "system32\WindowsPowerShell\v1.0") "powershell.exe"
$target_dir = ${Env:UserProfile}
$target_args = '-NoExit -Command "cd ' + "${Env:UserProfile}" + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\PowerShell.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin


#### Enable RSAT Tools ####
Write-Host "[-] Enabling Remote Server Administration Tools" -ForegroundColor Green
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD > $null
Write-Host "`t[+] This will take a minute..." -ForegroundColor Green
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-Powershell > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-ServerManager > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-CertificateServices > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-CertificateServices-CA > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-CertificateServices-OnlineResponder > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-DS > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-DS-SnapIns > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-DS-AdministrativeCenter > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-DS-NIS > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-AD-LDS > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-DHCP > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-DNS > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-FileServices > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-FileServices-Dfs > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-FileServices-Fsrm > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-FileServices-StorageMgmt > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-HyperV > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Roles-RDS > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-BitLocker > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-Clustering > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-GP > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-LoadBalancing > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-StorageExplorer > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-StorageManager > $null
cmd.exe /c dism /online /enable-feature /featurename:RemoteServerAdministrationTools-Features-Wsrm > $null
Write-Host "`t[+] Done!" -ForegroundColor Green
Start-Sleep -Seconds 1


#### Rename the computer ####
Write-Host "[+] Renaming host to 'commando'" -ForegroundColor Green
(Get-WmiObject win32_computersystem).rename("commando") | Out-Null
Write-Host "`t[-] Make sure to restart the machine for this change to take effect" -ForegroundColor Yellow
Write-Host "[+] Changing Desktop Background" -ForegroundColor Green


#### Update background ####
# Set desktop background to black
Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name Background -Value "0 0 0" -Force | Out-Null
# Set desktop wallpaper using WallpaperChanger utility
$wallpaperName = 'LightMale_Red.png'
$fileBackground = Join-Path $toolsDir $wallpaperName
$publicWallpaper = Join-Path ${env:public} $wallpaperName
$WallpaperChanger = Join-Path $toolsDir 'WallpaperChanger.exe'
Invoke-Expression "$WallpaperChanger $fileBackground 3"
# Copy background images
$backgroundzip = 'Backgrounds.7z'
$backgrounds = Join-Path $toolsDir $backgroundzip
Invoke-Expression "copy $backgrounds ${Env:USERPROFILE}\Pictures"
Write-Host "`t[+] Alternative backgrounds copied to ${Env:USERPROFILE}\Pictures" -ForegroundColor Yellow
# Copy Logos
$backgroundzip = 'CommandoVMLogos.7z'
$backgrounds = Join-Path $toolsDir $backgroundzip
Invoke-Expression "copy $backgrounds ${Env:USERPROFILE}\Pictures"
Write-Host "`t[+] Commando logos copied to ${Env:USERPROFILE}\Pictures" -ForegroundColor Yellow

foreach ($item in "0", "1", "2") {
  # Try to set it multiple times! Windows 10 is not consistent
  if ((Test-Path $publicWallpaper) -eq $false)
  {
    Copy-Item -Path $fileBackground -Destination $publicWallpaper -Force 
  }
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name Wallpaper -value $publicWallpaper
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name TileWallpaper -value "0" -Force
  Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name WallpaperStyle -value "6" -Force
  Sleep -seconds 3
  rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1, True
}
  
if ( -Not ([System.Environment]::OSVersion.Version.Major -eq 10)) {
  Invoke-Expression "$WallpaperChanger $fileBackground 1"
}


# Copy readme.txt on the Desktop
Write-Host "[+] Copying README.txt to Desktop" -ForegroundColor Green
$fileReadme = Join-Path $toolsDir 'readme.txt'
$desktopReadme = Join-Path ${Env:USERPROFILE} "Desktop\README.txt"
Copy-Item $fileReadme $desktopReadme

# Fix PATH issues with Python installers #18
$paths = @(
    "${Env:HomeDrive}\\Python37\\Scripts",
    "${Env:HomeDrive}\\Python37",
    "${Env:HomeDrive}\\Python27\\Scripts",
    "${Env:HomeDrive}\\Python27"
)

$env_path = cmd /c echo %PATH%
if ($env_path[-1] -ne ';') {
    $env_path += ';'
}
$old_path = $env_path
foreach ($p in $paths) {
    if ($env_path -match "$p[\\]{0,1};") {
        $env_path = $env_path -replace "$p[\\]{0,1};",""
        $env_path += $p.Replace("\\","\") + ";"
    }
}

if ($env_path -ne $old_path) {
    setx /M PATH $env_path
    refreshenv
}

# Remove desktop.ini files
Get-ChildItem -Path (Join-Path ${Env:UserProfile} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}
Get-ChildItem -Path (Join-Path ${Env:Public} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}


# Should be PS >5.1 now, enable transcription and script block logging
# More info: https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  New-ItemProperty -Path $psLoggingPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWORD -Force | Out-Null
  New-ItemProperty -Path $psLoggingPath -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force | Out-Null
  New-ItemProperty -Path $psLoggingPath -Name "OutputDirectory" -Value (Join-Path ${Env:UserProfile} "Desktop\PS_Transcripts") -PropertyType String -Force | Out-Null
  
  $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
  if (-Not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }
  New-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
}


# Done
Write-Host "[!] Done with configuration, shutting down Boxstarter..." -ForegroundColor Green