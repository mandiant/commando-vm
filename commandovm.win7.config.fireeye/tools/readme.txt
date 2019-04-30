       _________                                           .___      
       \_   ___ \  ____   _____   _____ _____    ____    __| _/____  
       /    \  \/ /  _ \ /     \ /     \\__  \  /    \  / __ |/  _ \ 
       \     \___(  <_> )  Y Y  \  Y Y  \/ __ \|   |  \/ /_/ (  <_> )
        \______  /\____/|__|_|  /__|_|  (____  /___|  /\____ |\____/ 
               \/             \/      \/     \/     \/      \/       
                        C O M P L E T E  M A N D I A N T                    
                             O F F E N S I V E   V M                        
                                   Version 1.1                                 
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
- Fixed misspellings in (this) Readme #42/#43
- Added Ruby and Ruby Devkit #1
- Updated Rubeus package to current version (1.4.2) #31

1.0.2 - April 10 2019
- Added missing 'seclists.fireeye' package to packages.json

1.0.1 - March 31 2019
- Used https instead of http to install boxstarter
