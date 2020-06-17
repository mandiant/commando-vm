$ErrorActionPreference = 'Continue'

$packageName = 'commandovm.win10.config.fireeye'
$toolsDir    = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

FE-Check-Reboot $packageName

### Commando Windows 10 Attack VM ###
Write-Host "[+] Beginning host configuration..." -ForegroundColor Green


# #### Disable services ####
Write-Host "[-] Disabling services" -ForegroundColor Green
Set-Service OpenVPNService -StartupType Manual -ErrorAction SilentlyContinue 
Set-Service OpenVPNServiceInteractive -StartupType Manual -ErrorAction SilentlyContinue 
Set-Service OpenVPNServiceLegacy -StartupType Manual -ErrorAction SilentlyContinue 
Write-Host "`t[+] Disabled OpenVPN Services" -ForegroundColor Green
Set-Service neo4j -StartupType Manual -ErrorAction SilentlyContinue
Stop-Service -Name neo4j 
Write-Host "`t[+] Disabled Neo4j" -ForegroundColor Green
Set-Service OpenSSHd -StartupType Manual -ErrorAction SilentlyContinue
Stop-Service -Name OpenSSHd -ErrorAction SilentlyContinue
Write-Host "`t[+] Disabled OpenSSH Service" -ForegroundColor Green
Start-Sleep -Seconds 2


#### Remove Desktop Shortcuts ####
Write-Host "[+] Cleaning up the Desktop" -ForegroundColor Green
$shortcut_path = "$Env:Public\Desktop\Boxstarter Shell.lnk"
if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }
$shortcut_path = "$Env:USERPROFILE\Desktop\Microsoft Edge.lnk"
if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
$shortcut_path = "$Env:USERPROFILE\Desktop\Google Chrome.lnk"
if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
$shortcut_path = "$Env:USERPROFILE\Desktop\VirusTotal Uploader 2.2.lnk"
if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force  -ErrorAction Ignore | Out-Null }
$shortcut_path = "$Env:Public\Desktop\Simple DNSCrypt.lnk"
if (Test-Path $shortcut_path) { Remove-Item $shortcut_path -Force -ErrorAction Ignore | Out-Null }


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
Write-Host "[+] Timestamps added to cmd prompt and PowerShell" -ForegroundColor Green

#### Fix shift+space in powershell
# https://superuser.com/questions/1365875/shiftspace-not-working-in-powershell
Set-PSReadLineKeyHandler -Chord Shift+Spacebar -Function SelfInsert
Write-Host "[+] Fixed shift+space keybinding in PowerShell" -ForegroundColor Green

#### Pin Items to Taskbar ####
Write-Host "[-] Pinning items to Taskbar" -ForegroundColor Green
# Explorer
$target_file = Join-Path ${Env:WinDir} "explorer.exe"
try {
  Write-Host "`tPinning $target_file to taskbar" -ForegroundColor Green
  syspin.exe "$target_file" 5386
} catch {
  FE-Write-Log "ERROR" "`tCould not pin $target_file to the taskbar"
}
# CMD prompt
$target_file = Join-Path ${Env:WinDir} "system32\cmd.exe"
$target_dir = ${Env:UserProfile}
$target_args = '/K "cd ' + ${Env:UserProfile} + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\cmd.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin
try {
  Write-Host "`tPinning $target_file to taskbar" -ForegroundColor Green
  syspin.exe "$shortcut" 5386
} catch {
  FE-Write-Log "ERROR" "`tCould not pin $target_file to the taskbar"
}
# Powershell
$target_file = Join-Path (Join-Path ${Env:WinDir} "system32\WindowsPowerShell\v1.0") "powershell.exe"
$target_dir = ${Env:UserProfile}
$target_args = '-NoExit -Command "cd ' + "${Env:UserProfile}" + '"'
$shortcut = Join-Path ${Env:UserProfile} "temp\PowerShell.lnk"
Install-ChocolateyShortcut -shortcutFilePath $shortcut -targetPath $target_file -Arguments $target_args -WorkingDirectory $target_dir -PinToTaskbar -RunasAdmin
try {
  Write-Host "`tPinning $target_file to taskbar" -ForegroundColor Green
  syspin.exe "$shortcut" 5386
} catch {
  FE-Write-Log "ERROR" "`tCould not pin $target_file to the taskbar"
}


#### Rename the computer ####
Write-Host "[+] Renaming host to 'commando'" -ForegroundColor Green
(Get-WmiObject win32_computersystem).rename("commando") | Out-Null
Write-Host "`t[-] Change will take effect after a restart" -ForegroundColor Yellow


#### Update background ####
Write-Host "[+] Changing Desktop Background" -ForegroundColor Green
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
  

# Copy readme.txt on the Desktop
Write-Host "[+] Copying README.txt to Desktop" -ForegroundColor Green
$fileReadme = Join-Path $toolsDir 'readme.txt'
$desktopReadme = Join-Path ${Env:USERPROFILE} "Desktop\README.txt"
try {
  Copy-Item $fileReadme $desktopReadme -Force -ErrorAction SilentlyContinue
} catch {
  Write-Host "Could not copy Readme to Desktop. Please visit github to review."
}

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
    try {
      setx /M PATH $env_path
      refreshenv
    } catch {
      Write-Host "Could not set PATH properly, please submit GitHub issue." -ForegroundColor Red
    }
}

# Remove desktop.ini files
try {
  Get-ChildItem -Path (Join-Path ${Env:UserProfile} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}
  Get-ChildItem -Path (Join-Path ${Env:Public} "Desktop") -Hidden -Filter "desktop.ini" -Force | foreach {$_.Delete()}
} catch {
  Write-Host "Could not remove desktop.ini files"
}

# Use AutoHotKey to modify various settings
$scripts = @(
  "UNCPathSoftening.ahk",           # "Softening" MS UNC Path Hardning stuffs....
  "EnableWinRM.ahk"                 # Enable WinRM
)
ForEach ($name in $scripts) {
  $script = Join-Path $toolsDir $name
  Write-Host "[+] Executing $script" -ForegroundColor Green
  AutoHotKey $script
}

# Should be PS >5.1 now, enable transcription and script block logging
# More info: https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
  Write-Host "[+] Enabling PowerShell Script Block Logging" -ForegroundColor Green
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
  Write-Host "`t[i] Powershell transcripts will be saved to the desktop." -ForegroundColor Green
}

# Done
Write-Host @"

[!]   Done with configuration, PLEASE ENSURE YOUR DESKTOP BACKGROUND HAS CHANGED.  [!]
[!] If your background has not changed, please open an administrative terminal and [!]
[!]    enter the following command: cinst -y commandovm.win10.config.fireeye -f    [!]

[i]   For more information see  https://github.com/fireeye/commando-vm/issues/139  [i]

"@ -ForegroundColor Red -BackgroundColor White

Write-Host @"

[+] Please enjoy your new VM. For any problems or ideas please submit GitHub issues, [+]
[+]     find @day1player in the BloodHound Slack #commando-vm channel, or email      [+]
[+]                             commandovm@fireeye.com                               [+]

"@ -ForegroundColor White -BackgroundColor DarkGreen
