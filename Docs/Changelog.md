# Changelog

## 3.0 - August 9 2023
- Completely rebuilt everything

## 2021.2 - July 14 2021
- Require users to disable Defender before installing
  * Too many issues arise from Defender magically turning itself back on. Disabling defender with the preconfig script has been unreliable since Win10 1909.
- removed update requirement (legacy  requirement for Windows 7. Windows 7 support was  removed last year)
- Added support for Windows 10 20H2 and 21H1
- Removed vcpython27 #204
- updated proxycap install args #203, #200. #196
- updated sqlitebrowser.fireeye to remove newly created desktop shortcuts #200
- Closed issues #203, #204, #202, #200, #196, #195, #192, #191, #190, #189, #188, #186, #185, #184, #177, #175, #174, #170, #169, #160, #134, #133

## 2020.2 - June 17 2020
- Added support for Windows 10 2004
- Corrected syspin verb #124
- Removed WSL from default install #146, #120
- Removed Hyper V from default install #146, #120
- Removed Kali from default install #95, #120
- Removed Docker from default install #95, #120
- Created wsl.fireeye package #95, #120
- Created hyperv.fireeye package #95, #120 
- Created multiple install profiles #95, #120
  - Default, NestedV, Lite, Full, and Developer
- Removed some dependencies causing %PATH% variable to be truncated to 1024 characters #141
- Added logic to help speed up install
- Removed dependency on custom libraries file #131
- Added custom logging for installation of packages #70
- Fixed bug in autohotkey script for unhardening of UNC paths #68
- Updated Readme #140

## 2020.1 - March 3 2020
- added logic to attempt automatically updating system #88
- added qbittorrent #88
- added dbeaver #88
- added hfsexplorer #88
- added lockhunter #88
- fixed typo for PwnedPasswordsNTLM in packages.json #101
- added BeRoot
- added BloodHound Custom Queries - Hausec
- added Dumpert
- added Recon-AD
- added Net-GPPPassword
- added Gadget2JScript
- added OffensiveCSharp - matterpreter
- added powercat
- added Privesc - enjoiz
- added PSBits
- added ThreadContinue
- added SysWhispers
- added TikiTorch
- added Virus Total Uploader #88
- added NirLauncher #88
- added SimpleDnsCrypt #88
- added Tor Browser #88
- added HeidiSQL #88
- added HTTP File Server #88
- Removed support for Windows 7 (install should still work, but is no longer maintained)
- improved error handling for commandovm.win10.config.fireeye package
- updated commandovm.win10.preconfig.fireeye
- Fixed taskbar pinning on 1903 (still not working for 1909)
- Updated install instructions on readme
- Updated ~45 packages
- Removed Watson binaries (static binaries are not updated in this repo)
- Removed PoshC2 (deprecated, will look at supporting PoshC2 Python)
- Removed Covenant (will support again in a future release)
- Removed Elite (deprecated)

## 2.0 - August 5 2019
- Added Kali Linux https://www.kali.org
- Added Docker https://www.docker.com #88
- Added SpiderFoot https://github.com/smicallef/spiderfoot #84
- Added Amass https://github.com/OWASP/Amass
- Added customization support #42, #25 

## 1.3 - June 28 2019
- Added RottenPotatoNG https://github.com/breenmachine/RottenPotatoNG #63
- Added Juicy Potato https://github.com/ohpe/juicy-potato #63, #64
- Added Watson https://github.com/rasta-mouse/Watson #64
- Added PwndPasswordsNTLM https://github.com/JacksonVD/PwnedPasswordsNTLM #67
- Added FOCA https://github.com/JacksonVD/PwnedPasswordsNTLM #71 
- Added Vulcan https://github.com/praetorian-code/vulcan
- Added SharpClipHistory https://github.com/mwrlabs/SharpClipHistory
- Added NetRipper https://github.com/NytroRST/NetRipper
- Added RobotsDisallowed https://github.com/danielmiessler/RobotsDisallowed
- Added Probable-Wordlists https://github.com/berzerk0/Probable-Wordlists
- Added SharpSploit https://github.com/cobbr/SharpSploit
- Changed WinRM configuration #65
- Un-hardened UNC file paths #68
- Fixed install issues with Covenant #61, #76

## 1.2 - May 31 2019
- Added recommended hardware settings #20, #17
- Added DomainPasswordSpray https://github.com/dafthack/DomainPasswordSpray #2
- Added GoBuster https://github.com/OJ/gobuster #39
- Added Wfuzz https://github.com/xmendez/wfuzz #40
- Added Notepad++ #30
- Added TextFX plugin for Notepad++
- Added Explorer Suite (CFF Explorer)

## 1.1 - April 30 2019
- Added AD-Control-Paths https://github.com/ANSSI-FR/AD-control-paths/releases
- Added DefenderCheck https://github.com/matterpreter/DefenderCheck
- Added dnsrecon https://github.com/darkoperator/dnsrecon
- Added EvilClippy https://github.com/outflanknl/EvilClippy
- Added NtdsAudit https://github.com/Dionach/NtdsAudit
- Added SharpExec https://github.com/anthemtotheego/SharpExec
- Added Subdomain-Bruteforce https://github.com/visualbasic6/subdomain-bruteforce
- Fixed issue #18 with PATH 
- Added Commando Logos with transparent backgrounds to $Home\Pictures
- Pinned Firefox to Taskbar
- Fixed misspellings in Readme #42/#43
- Added Ruby and Ruby Devkit #1
- Updated Rubeus package to current version (1.4.2) #31

1.0.2 - April 10 2019
- Added missing 'seclists.fireeye' package to packages.json #38

1.0.1 - March 31 2019
- Used https instead of http to install boxstarter #10