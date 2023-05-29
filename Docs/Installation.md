# Installing CommandoVM

This page lists the steps necessary to install CommandoVM:
- [Requirements](#requirements)
- [Pre-Install Steps](#pre-install-steps)
- [Graphical Install](#graphical-install)
- [Command-Line Install](#command-line-install)

## Requirements

- Windows 10 22H2
- Windows 11 TBA
- Minimum 70 GB Hard Drive
- Minimum 4 GB RAM

## Pre-Install Steps

**Disclaimer**
> Please **do not skip** this section. The following steps are **required** for a successful CommandoVM install. The installer will not allow you to continue until you satisfy these requirements. You may skip them by passing the `-skipChecks` flag if you know what you are doing, but we do not recommend it and we cannot help you if you run into issues as a result of it.

### Supported Operating System

CommandoVM currently supports Windows 10 22H2 and Windows 11 TBA releases. We plan to eventually drop support for Windows 10 because it no longer gets feature updates that may be important for penetration testers and users. We recommend you to install CommandoVM on a Windows 11 system.

### Running in a Virtual Machine

You should never install CommandoVM on your host machine. CommandoVM makes irreversible changes to the system that you cannot uninstall. We recommend installing it on a virtual machine in [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [VMware Workstation](https://www.vmware.com/products/workstation-pro.html).

### Storage Requirement

Windows itself takes up significant space on disk and CommandoVM installs a large number of additional packages and tools. Ensure that you have at least **70GB** of storage in your VM. If you opt-in to install the **Full** CommandoVM profile, you will most certainly need a lot more than that.

### Running as Administrator

CommandoVM uses Chocolatey and Boxstarter to install its packages. Installing packages requires Administrator rights, so you must run your terminal as Administrator as shown on the image below.
![run terminal as administrator](../Images/Docs/runasadmin.png)

### PowerShell Execution Policy

By default PowerShell restricts scripts from being loaded on Windows Workstations and requires them to be signed by a trusted publisher on Windows servers. CommandoVM installation is performed using PowerShell, so you need to disable these restrictions using the following PowerShell command from an elevated prompt:
```powershell
Set-ExecutionPolicy Unrestricted
```

You can validate that your changes were successful with the following command:
```powershell
Get-ExecutionPolicy
```

### Windows Defender and Tamper Protection

In the past CommandoVM would try to programmatically disable Windows Defender for you. Unfortunately Windows Defender is constantly evolving, so we cannot keep up with the changes. You **must** disable Windows Defender and Tamper Protection manually before starting the install. It is not enough to simply disable Real-Time Protection, because **it will become re-enabled after a reboot**.

See our [Defender Documentation](Defender.md) page for the latest methods of disabling it known to us on Windows 10 and 11.

> **WARNING:** If you do not properly disable Windows Defender, your installation will most certainly fail

## Graphical Install

WIP

## Command-Line Install

WIP