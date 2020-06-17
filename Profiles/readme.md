# Commando VM Managed Profiles 
If you would like a more specialized loadout for your instance of Commando VM please check out our provided profiles. These profiles exercise our [Custom Install](https://github.com/fireeye/commando-vm#custom-install) feature implemented with the [2.0 release of Commando](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html) last year. These example profiles allow you to build custom, specific, purpose-built VMs.

# Profile Details
 
 We currently maintain five profiles for varying purposes:

- Default
  - The [`default`](https://github.com/fireeye/commando-vm/blob/master/commandovm.win10.installer.fireeye/tools/packages.json) install contains numerous packages for pentesting. This install will come with almost everything except for Nested Virtualization. This package is installed by default and therefore there are no special arguments when installing.
- NestedV
  - The [`nestedv.json`](https://github.com/fireeye/commando-vm/blob/master/Profiles/nestedv.json) package is a copy of the `default` package, but supports Nested Virtualization such as Docker and the Linux Subsystem.
- Lite
  - The [`lite.json`](https://github.com/fireeye/commando-vm/blob/master/Profiles/lite.json) profile contains only the bare minimum tools essential for pentesting. Tools such as Nmap, Burp, PowerSploit, Ghostpack, and so on. This profile does not install Python or other large installation packages.
- Full
  - The [`full.json`](https://github.com/fireeye/commando-vm/blob/master/Profiles/full.json) package is the whole shebang. Every package we deem suitable for Commando.
- Developer
  - The [`developer.json`](https://github.com/fireeye/commando-vm/blob/master/Profiles/developer.json) package will install developer tools onto the target such as Visual Studio, VS Code, Sublime Text, Sysinternals, and so on.

# Installation

Please ensure to follow steps outlined below. <br> These steps are modified from our [Custom Install](https://github.com/fireeye/commando-vm#custom-install) instructions. You can find more detailed instructions on our [2.0 release of Commando blog](https://www.fireeye.com/blog/threat-research/2019/08/commando-vm-customization-containers-kali.html).

1.	Download the zip from https://github.com/fireeye/commando-vm into your Downloads folder.
1.	Open an administrative PowerShell window and enable script execution.
`Set-ExecutionPolicy Unrestricted -f`
1.	Change to the unzipped project directory.
`cd ${Env:UserProfile}\Downloads\commando-vm-master\commando-vm-master\`
1.  Unblock the install script with `Unblock-File .\install.ps1`
1.	Execute the install with the `-profile_file` argument.
`.\install.ps1 -profile_file .\Profiles\<profile-name>.json`

| Profile | Recommended Disk Space | Recommended RAM | Install Command |
| :----:  |    :----:   |   :----:   | :----: |
| Default | 40 GB+ | 4 GB+ | `.\install.ps1` |
| NestedV | 50 GB+ | 4 GB+ |  `.\install.ps1 -profile_file .\Profiles\nestedv.json` |
| Lite | 35 GB+ | 4 GB+ |  `.\install.ps1 -profile_file .\Profiles\lite.json` |
| Full | 70 GB+ | 4 GB+ |  `.\install.ps1 -profile_file .\Profiles\full.json` |
| Developer | 50 GB+ | 4 GB+ |  `.\install.ps1 -profile_file .\Profiles\developer.json` |

> Note: You will be warned about disk space during install for having less than 60 GB of storage. Please ensure you have the recommended disk space shown above before bypassing the warning.
