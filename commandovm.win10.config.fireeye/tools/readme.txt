       _________                                           .___      
       \_   ___ \  ____   _____   _____ _____    ____    __| _/____  
       /    \  \/ /  _ \ /     \ /     \\__  \  /    \  / __ |/  _ \ 
       \     \___(  <_> )  Y Y  \  Y Y  \/ __ \|   |  \/ /_/ (  <_> )
        \______  /\____/|__|_|  /__|_|  (____  /___|  /\____ |\____/ 
               \/             \/      \/     \/     \/      \/       
                        C O M P L E T E  M A N D I A N T                    
                             O F F E N S I V E   V M                        
                                   Version 1.3                                 
               _____________________________________________________          

                                   Developed by                                
                                   Jake Barteaux                               
                                 Proactive Services  
                                  Blaine Stancill                          
                                    Nhan Huynh   
                     FireEye Labs Advanced Reverse Engineering                            
______________________________________________________________________________ 

Welcome to Commando VM - Red Team Edition! This distribution contains a number
of Tools and configurations to enhance Red Teaming and Penetration Testing.

Please make sure to take a snapshot after installing so you can always revert
back if you have issues.

This image has the Chocolatey package manager installed, and you can continue to
customize this machine with any package from the Chocolatey repository - 
https://chocolatey.org/packages.

Try this:
  choco install github 
Or:
  cinst github

To keep this distribution up to date, type this into an Administrative terminal:
  cup all

As this is a Red Teaming and Penetration Testing build certain protections have
been disabled, and certain 'risky' features and tweaks have been enabled.

Please enjoy the VM and submit any feedback or feature requests as github 
issues here:
https://github.com/fireeye/commando-vm

Changelog:
1.3 - June 28 2019
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
- Fixed install issues with Covenant #61, #78

1.2 - May 31 2019
- Added recommended hardware settings #20, #17
- Added DomainPasswordSpray https://github.com/dafthack/DomainPasswordSpray
- Added GoBuster https://github.com/OJ/gobuster #39
- Added Wfuzz https://github.com/xmendez/wfuzz #40
- Added Notepad++ #30
- Added TextFX plugin for Notepad++
- Added Explorer Suite (CFF Explorer)

1.1 - April 30 2019
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
