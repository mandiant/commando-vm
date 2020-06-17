                                                                   
       _________                                           .___      
       \_   ___ \  ____   _____   _____ _____    ____    __| _/____  
       /    \  \/ /  _ \ /     \ /     \\__  \  /    \  / __ |/  _ \ 
       \     \___(  <_> )  Y Y  \  Y Y  \/ __ \|   |  \/ /_/ (  <_> )
        \______  /\____/|__|_|  /__|_|  (____  /___|  /\____ |\____/ 
               \/             \/      \/     \/     \/      \/       
                        C O M P L E T E  M A N D I A N T                    
                             O F F E N S I V E   V M                        
                                  Version 2020.2                                 
                              commandovm@fireeye.com
               _____________________________________________________          

                                    Created by                                
                             Jake Barteaux @day1player                              
                                 Mandiant Red Team  
                          Blaine Stancill @MalwareMechanic                           
                                    Nhan Huynh   
                     FireEye Labs Advanced Reverse Engineering                            
______________________________________________________________________________ 

<p align="center">
  <img width="300" src="https://github.com/fireeye/commando-vm/blob/master/Commando.png?raw=true" alt="Commando VM"/>
</p>  

Welcome to CommandoVM - a fully customizable, Windows-based security distribution for penetration testing and red teaming.

For detailed install instructions or more information please see our [blog](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html)

Installation (Install Script)
=============================

Requirements
------------
* Windows 10 1803, 1809, 1903, 1909, or 2004
> Insider Preview editions of Windows are not supported
* 60 GB Hard Drive
* 2 GB RAM

Recommended
-----------
* Windows 10 2004
* 80+ GB Hard Drive
* 4+ GB RAM
* 2 network adapters

Instructions
============
Standard install
----------------
1. Create and configure a new Windows Virtual Machine
  > Ensure VM is updated completely. You may have to check for updates, reboot, and check again until no more remain 
2.  Take a snapshot of your machine!
3.  Download and copy `install.ps1` on your newly configured machine. 
4.  Open PowerShell as an Administrator
5.  Unblock the install file by running `Unblock-File .\install.ps1`
6.  Enable script execution by running `Set-ExecutionPolicy Unrestricted -f`
7.  Finally, execute the installer script as follows:
   * `.\install.ps1`
   * You can also pass your password as an argument: `.\install.ps1 -password <password>`
  
The script will set up the Boxstarter environment and proceed to download and install the Commando VM environment. You will be prompted for the administrator password in order to automate host restarts during installation. If you do not have a password set, hitting enter when prompted will also work.

Custom install
--------------
> Please see our [custom profiles](https://github.com/fireeye/commando-vm/tree/master/Profiles) for more custom install options or create your own following the instructions below.
1.	Download the zip from https://github.com/fireeye/commando-vm into your Downloads folder.
2.	Decompress the zip and edit the `${Env:UserProfile}\Downloads\commando-vm-master\commando-vm-master\profile.json` file by removing tools or adding tools in the “packages” section. You can add any package listed in our [package list](https://github.com/fireeye/commando-vm/blob/master/packages.csv) or any package from the [chocolatey repository](https://chocolatey.org/packages).
3.	Open an administrative PowerShell window and enable script execution.
`Set-ExecutionPolicy Unrestricted -f`
4.	Change to the unzipped project directory.
`cd ${Env:UserProfile}\Downloads\commando-vm-master\commando-vm-master\`
5.  Unblock the install file by running `Unblock-File .\install.ps1`
6.	Take a snapshot of your machine!
7. Execute the install with the `-profile_file` argument.
`.\install.ps1 -profile_file .\profile.json`

For more detailed instructions about custom installations, see our [blog](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html)

Installing a new package
========================

Commando VM uses the [Chocolatey](https://chocolatey.org/) Windows package manager. It is easy to install a new package. For example, enter the following command as Administrator to deploy Github Desktop on your system:

    cinst github

You can find packages to install from our [package list](https://github.com/fireeye/commando-vm/blob/master/packages.csv), which hosts more than just pentesting tools, or from the [chocolatey repository](https://chocolatey.org/packages).


Staying up to date
==================

Type the following command to update all of the packages to the most recent version:

    cup all


Available Tools
===============

### Active Directory Tools
- Remote Server Administration Tools (RSAT)
- SQL Server Command Line Utilities
- Sysinternals

### Command & Control
- Covenant
- WMImplant
- WMIOps

### Developer Tools
- Dep
- Git
- Go
- Java
- Python 2
- Python 3 (default)
- Ruby
- Ruby Devkit
- Visual Studio 2017 Build Tools (Windows 10)
- Visual Studio Code

### Docker
- Amass
- SpiderFoot

### Evasion
- CheckPlease
- Demiguise
- DefenderCheck
- DotNetToJScript
- Invoke-CradleCrafter
- Invoke-DOSfuscation
- Invoke-Obfuscation
- Invoke-Phant0m
- Not PowerShell (nps)
- PS>Attack
- PSAmsi
- Pafishmacro
- PowerLessShell
- PowerShdll
- StarFighters
- SysWhispers

### Exploitation
- ADAPE-Script
- API Monitor
- CrackMapExec
- CrackMapExecWin
- DAMP
- Dumpert
- EvilClippy
- Exchange-AD-Privesc
- FuzzySec's PowerShell-Suite
- FuzzySec's Sharp-Suite
- GadgetToJScript
- Generate-Macro
- GhostPack
  - Rubeus
  - SafetyKatz
  - Seatbelt
  - SharpDPAPI
  - SharpDump
  - SharpRoast
  - SharpUp
  - SharpWMI
- GoFetch
- Impacket
- Invoke-ACLPwn
- Invoke-DCOM
- Invoke-PSImage
- Invoke-PowerThIEf
- Juicy Potato
- Kali Binaries for Windows
- LuckyStrike
- MetaTwin
- Metasploit
- Mr. Unikod3r's RedTeamPowershellScripts
- NetshHelperBeacon
- Nishang
- Orca
- PSBits
- PSReflect
- PowerLurk
- PowerPriv
- PowerSploit
- PowerUpSQL
- PrivExchange
- RottenPotatoNG
- Ruler
- SharpClipHistory
- SharpExchangePriv
- SharpExec
- SpoolSample
- SharpSploit
- ThreadContinue
- TikiTorch
- UACME
- impacket-examples-windows
- vssown
- Vulcan

### Information Gathering
- ADACLScanner
- ADExplorer
- ADOffline
- ADRecon
- BeRoot
- BloodHound
- BloodHound-Custom-Queries (Hausec)
- dnsrecon
- FOCA
- Get-ReconInfo
- GoBuster
- GoWitness
- Net-GPPPassword
- NetRipper
- Nmap
- PowerView
  - Dev branch included
- Privesc (enjoiz)
- Recon-AD
- SharpHound
- SharpView
- SpoolerScanner
- Watson

### Kali Linux
- kali-linux-default
- kali-linux-xfce
- VcXsrv

### Networking Tools
- Citrix Receiver
- OpenVPN
- Powercat
- Proxycap
- PuTTY
- Telnet
- VMWare Horizon Client
- VMWare vSphere Client
- VNC-Viewer
- WinSCP
- Windump
- Wireshark

### Password Attacks
- ASREPRoast
- CredNinja
- DomainPasswordSpray
- DSInternals
- Get-LAPSPasswords
- Hashcat
- Internal-Monologue
- Inveigh
- Invoke-TheHash
- KeeFarce
- KeeThief
- LAPSToolkit
- MailSniper
- Mimikatz
- Mimikittenz
- RiskySPN
- SessionGopher

### Reverse Engineering
- DNSpy
- Flare-Floss
- ILSpy
- PEview
- Windbg
- x64dbg

### Utilities
- 7zip
- Adobe Reader
- AutoIT
- Cmder
- CyberChef
- Explorer Suite
- Gimp
- Greenshot
- Hashcheck
- HeidiSQL
- Hexchat
- HTTP File Server (hfs)
- HxD
- Keepass
- MobaXterm
- Mozilla Thunderbird
- Neo4j Community Edition
- NirLauncher
- Notepad++
- Pidgin
- Process Hacker 2
- qBittorrent
- SQLite DB Browser
- Screentogif
- Shellcode Launcher
- SimpleDNSCrypt
- SQLite DB Browser
- Sublime Text 3
- Tor Browser
- TortoiseSVN
- VLC Media Player
- yEd Graph Tool

### Vulnerability Analysis
- AD Control Paths
- Egress-Assess
- Grouper2
- NtdsAudit
- PwnedPasswordsNTLM
- zBang

### Web Applications
- Burp Suite
- Fiddler
- Firefox
- OWASP Zap
- Subdomain-Bruteforce
- Wfuzz

### Wordlists
- FuzzDB
- PayloadsAllTheThings
- SecLists
- Probable-Wordlists
- RobotsDisallowed

Legal Notice
============
<pre>This download configuration script is provided to assist penetration testers
in creating handy and versatile toolboxes for offensive engagements. It provides 
a convenient interface for them to obtain a useful set of pentesting Tools directly 
from their original sources. Installation and use of this script is subject to the 
Apache 2.0 License.
 
You as a user of this script must review, accept and comply with the license
terms of each downloaded/installed package listed below. By proceeding with the
installation, you are accepting the license terms of each package, and
acknowledging that your use of each package will be subject to its respective
license terms.

Licenses for each package can be found in the packages.csv file for this repository.
</pre>
