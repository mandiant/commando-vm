
# CommandoVM & HashiCorp's Packer

Welcome to the packer builder of CommandoVM - a fully automated installation of the customizable commandvm platform.

## Requirements

* a hypervisor ( below are current hypervisors )
  * [Virtualbox](https://www.virtualbox.org/wiki/Downloads)
* HashiCorp's [packer](https://www.packer.io/downloads)
* [packer provisioner windows update](https://github.com/rgl/packer-provisioner-windows-update)
* 60 GB Hard Drive
* 2 GB RAM

## Recommended

* 80+ GB Hard Drive
* 4+ GB RAM

# Instructions

## Standard install

1. make sure you have all the [pre-reqs](#requirements).
2. Download the zip from [https://github.com/fireeye/commando-vm](https://github.com/fireeye/commando-vm).
3. Decompress the zip and cd into the [win10_1809 folder](/packer/win10_1809/).
4. run the following command: `packer build win10_1809_virtualbox_iso_to_finish.json`.
   > if you don't have packer in you path, then you will have to specify the full path to the packer binary.
  
This will automate the whole process of creating the base vm, doing a windows installation, and then installing all the necessary CommandoVM components.

## Custom install

1. make sure you have all the [pre-reqs](#requirements).
2. Download the zip from [https://github.com/fireeye/commando-vm](https://github.com/fireeye/commando-vm) into your Downloads folder.
3. Decompress the zip and cd into the [win10_1809 folder](/packer/win10_1809/).
4. Modify any of the .json files to your pleasure.
5. run the following command: `packer build win10_1809_virtualbox_iso_to_finish.json`.

### Other resources

* packer documentation: [https://www.packer.io/docs](https://www.packer.io/docs)
* current builder(s):
  * [Virtualbox](https://www.packer.io/docs/builders/virtualbox)
* current provisioner(s):
  * [File](https://www.packer.io/docs/provisioners/file)
  * [Windows Shell](https://www.packer.io/docs/provisioners/windows-shell)
  * [Windows Restart](https://www.packer.io/docs/provisioners/windows-restart)

### Possible Install Type

#### Base Installation

The `win10_1809_virtualbox_iso_to_base.json` build will take an ISO and create a base windows vm, that is prepared for CommandoVM to install. This would be used well with a custom CommandoVM installation, where you would modify your profile to your liking.

#### Snapshot Installation

The `win10_1809_virtualbox_snapshot_to_finish.json` build will take an already existing virtual machine name: `Windows_10_1809_x64_commando` ( rename your vm this or change this in the config if you don't want to use that name ) and a snapshot named: `Snapshot_1` (which you will have to create), and then do the CommandoVM installation for you with the default profile. Also, you will need to pass a parameter of `-var 'profile_file_name=<profile_you_want>'` to understand profiles better go [here](/Profiles/).

**NOTE:** you will need to either have your username and password or a username and password created in order to use this install method with Administrative rights to the vm:

* username: `vagrant`
* password: `vagrant`

**NOTE:** you will need to configure your machine up to the CommandoVM standards (i.e. removing tamper protection, etc...), and also you will have to configure the machine similar to the following commands executed [here](/packer/win10_1809/floppy/Autounattend.xml)
