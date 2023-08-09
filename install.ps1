<#
    .SYNOPSIS
        Installation script for CommandoVM.
    .DESCRIPTION
        Placeholder
    .PARAMETER cli
        Switch parameter to skip customization GUI.
    .PARAMETER victim
        Switch parameter to to install the victim profile.
    .PARAMETER skipChecks
        Switch parameter to skip validation checks (not recommended).
    .PARAMETER password
        [CLI INSTALL] Current user password to allow reboot resiliency via Boxstarter
    .PARAMETER noPassword
        [CLI INSTALL] Used when the user password is not set or is blank
    .PARAMETER customProfile
        [CLI INSTALL] Path to a configuration XML file. May be a file path or URL.
    .EXAMPLE
        .\install.ps1
    .LINK
        https://github.com/mandiant/commando-vm
        https://github.com/mandiant/VM-Packages
#>

param (
    [switch]$cli,
    [switch]$victim,
    [switch]$skipChecks,
    [switch]$noPassword,
    [string]$password,
    [string]$customProfile
)

$asciiArt = @'
▄████▄   ▒█████   ███▄ ▄███▓ ███▄ ▄███▓ ▄▄▄       ███▄    █ ▓█████▄  ▒█████  
▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██▀ ██▌▒██▒  ██▒
▒▓█    ▄ ▒██░  ██▒▓██    ▓██░▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒░██   █▌▒██░  ██▒
▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██ ▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█▄   ▌▒██   ██░
▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░░▒████▓ ░ ████▓▒░
░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ 
  ░  ▒     ░ ▒ ▒░ ░  ░      ░░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░ ░ ▒  ▒   ░ ▒ ▒░ 
░        ░ ░ ░ ▒  ░      ░   ░      ░     ░   ▒      ░   ░ ░  ░ ░  ░ ░ ░ ░ ▒  
░ ░          ░ ░         ░          ░         ░  ░         ░    ░        ░ ░  
░                                                             ░               
'@

Add-Type -AssemblyName System.Drawing

$errorColor = [System.Drawing.ColorTranslator]::FromHtml("#c80505")
$successColor = [System.Drawing.ColorTranslator]::FromHtml("#417505")
$grayedColor = [System.Drawing.ColorTranslator]::FromHtml("#959393")
$skippedColor = [System.Drawing.ColorTranslator]::FromHtml("#f59f00")
$skippedColor = [System.Drawing.ColorTranslator]::FromHtml("#f59f00")

# Load the GUI controls
if (-not $cli.IsPresent) {

    Add-Type -AssemblyName System.Windows.Forms
  
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $iconPath = Join-Path $PSScriptRoot "Images/mandiant.png"
    $icon = [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap -ArgumentList $iconPath).GetHicon())

    #################################################################################################
    ################################ Installer Checks Form Controls #################################
    #################################################################################################

    $CommandoChecksManager           = New-Object system.Windows.Forms.Form
    $CommandoChecksManager.ClientSize  = New-Object System.Drawing.Point(510,376)
    $CommandoChecksManager.text      = "CommandoVM Pre-Install Checks"
    $CommandoChecksManager.TopMost   = $true
    $CommandoChecksManager.Icon      = $icon
    $CommandoChecksManager.StartPosition = 'CenterScreen'
    
    $ChecksPanel                     = New-Object system.Windows.Forms.Panel
    $ChecksPanel.height              = 274
    $ChecksPanel.width               = 89
    $ChecksPanel.location            = New-Object System.Drawing.Point(365,8)
    
    $InstallChecksGroup              = New-Object system.Windows.Forms.Groupbox
    $InstallChecksGroup.height       = 289
    $InstallChecksGroup.width        = 462
    $InstallChecksGroup.text         = "Installation Checks"
    $InstallChecksGroup.location     = New-Object System.Drawing.Point(23,14)
    
    ################################# Check Labels #################################

    $RunningAsAdminLabel             = New-Object system.Windows.Forms.Label
    $RunningAsAdminLabel.text        = "Running as Administrator"
    $RunningAsAdminLabel.AutoSize    = $true
    $RunningAsAdminLabel.width       = 25
    $RunningAsAdminLabel.height      = 10
    $RunningAsAdminLabel.location    = New-Object System.Drawing.Point(15,18)
    $RunningAsAdminLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $ExecutionPolicyLabel            = New-Object system.Windows.Forms.Label
    $ExecutionPolicyLabel.text       = "Execution Policy Unrestricted"
    $ExecutionPolicyLabel.AutoSize   = $true
    $ExecutionPolicyLabel.width      = 25
    $ExecutionPolicyLabel.height     = 10
    $ExecutionPolicyLabel.location   = New-Object System.Drawing.Point(15,59)
    $ExecutionPolicyLabel.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $WindowsDefenderLabel           = New-Object system.Windows.Forms.Label
    $WindowsDefenderLabel.text      = "Windows Defender Disabled"
    $WindowsDefenderLabel.AutoSize  = $true
    $WindowsDefenderLabel.width     = 25
    $WindowsDefenderLabel.height    = 10
    $WindowsDefenderLabel.location  = New-Object System.Drawing.Point(15,104)
    $WindowsDefenderLabel.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $WindowsReleaseLabel             = New-Object system.Windows.Forms.Label
    $WindowsReleaseLabel.text        = "Compatible Windows Release"
    $WindowsReleaseLabel.AutoSize    = $true
    $WindowsReleaseLabel.width       = 25
    $WindowsReleaseLabel.height      = 10
    $WindowsReleaseLabel.location    = New-Object System.Drawing.Point(15,149)
    $WindowsReleaseLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $RunningVMLabel                  = New-Object system.Windows.Forms.Label
    $RunningVMLabel.text             = "Running in a Virtual Machine"
    $RunningVMLabel.AutoSize         = $true
    $RunningVMLabel.width            = 25
    $RunningVMLabel.height           = 10
    $RunningVMLabel.location         = New-Object System.Drawing.Point(15,193)
    $RunningVMLabel.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $EnoughHardStorageLabel          = New-Object system.Windows.Forms.Label
    $EnoughHardStorageLabel.text     = "Enough Hard Drive Space"
    $EnoughHardStorageLabel.AutoSize  = $true
    $EnoughHardStorageLabel.width    = 25
    $EnoughHardStorageLabel.height   = 10
    $EnoughHardStorageLabel.location  = New-Object System.Drawing.Point(15,239)
    $EnoughHardStorageLabel.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    ################################# Check Boolean Controls #################################
    
    $RunningAsAdmin                  = New-Object system.Windows.Forms.Label
    $RunningAsAdmin.text             = "False"
    $RunningAsAdmin.AutoSize         = $true
    $RunningAsAdmin.width            = 25
    $RunningAsAdmin.height           = 10
    $RunningAsAdmin.location         = New-Object System.Drawing.Point(24,18)
    $RunningAsAdmin.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $RunningAsAdmin.ForeColor        = $errorColor
    
    $ExecutionPolicy                 = New-Object system.Windows.Forms.Label
    $ExecutionPolicy.text            = "False"
    $ExecutionPolicy.AutoSize        = $true
    $ExecutionPolicy.width           = 25
    $ExecutionPolicy.height          = 10
    $ExecutionPolicy.location        = New-Object System.Drawing.Point(24,63)
    $ExecutionPolicy.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $ExecutionPolicy.ForeColor       = $errorColor
    
    $WindowsDefender                = New-Object system.Windows.Forms.Label
    $WindowsDefender.text           = "False"
    $WindowsDefender.AutoSize       = $true
    $WindowsDefender.width          = 25
    $WindowsDefender.height         = 10
    $WindowsDefender.location       = New-Object System.Drawing.Point(24,108)
    $WindowsDefender.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $WindowsDefender.ForeColor      = $errorColor
    
    $WindowsRelease                  = New-Object system.Windows.Forms.Label
    $WindowsRelease.text             = "False"
    $WindowsRelease.AutoSize         = $true
    $WindowsRelease.width            = 25
    $WindowsRelease.height           = 10
    $WindowsRelease.location         = New-Object System.Drawing.Point(24,150)
    $WindowsRelease.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $WindowsRelease.ForeColor        = $errorColor
    
    $RunningVM                       = New-Object system.Windows.Forms.Label
    $RunningVM.text                  = "False"
    $RunningVM.AutoSize              = $true
    $RunningVM.width                 = 25
    $RunningVM.height                = 10
    $RunningVM.location              = New-Object System.Drawing.Point(24,195)
    $RunningVM.Font                  = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $RunningVM.ForeColor             = $errorColor
    
    $EnoughHardStorage               = New-Object system.Windows.Forms.Label
    $EnoughHardStorage.text          = "False"
    $EnoughHardStorage.AutoSize      = $true
    $EnoughHardStorage.width         = 25
    $EnoughHardStorage.height        = 10
    $EnoughHardStorage.location      = New-Object System.Drawing.Point(24,241)
    $EnoughHardStorage.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $EnoughHardStorage.ForeColor     = $errorColor
    
    ################################# Check Tooltip Controls #################################

    $RunningVMTooltip                = New-Object system.Windows.Forms.Label
    $RunningVMTooltip.text           = "Only run this script inside a Virtual Machine"
    $RunningVMTooltip.AutoSize       = $true
    $RunningVMTooltip.width          = 25
    $RunningVMTooltip.height         = 10
    $RunningVMTooltip.location       = New-Object System.Drawing.Point(15,219)
    $RunningVMTooltip.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $RunningVMTooltip.ForeColor      = $grayedColor
    
    $WindowsReleaseTooltip           = New-Object system.Windows.Forms.Label
    $WindowsReleaseTooltip.text      = "Ensure your Windows version is supported"
    $WindowsReleaseTooltip.AutoSize  = $true
    $WindowsReleaseTooltip.width     = 25
    $WindowsReleaseTooltip.height    = 10
    $WindowsReleaseTooltip.location  = New-Object System.Drawing.Point(15,175)
    $WindowsReleaseTooltip.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $WindowsReleaseTooltip.ForeColor  = $grayedColor
    
    $WindowsDefenderTooltip            = New-Object system.Windows.Forms.Label
    $WindowsDefenderTooltip.text       = "Disable Windows Defender and Tamper Protection"
    $WindowsDefenderTooltip.AutoSize   = $true
    $WindowsDefenderTooltip.width      = 25
    $WindowsDefenderTooltip.height     = 10
    $WindowsDefenderTooltip.location   = New-Object System.Drawing.Point(15,130)
    $WindowsDefenderTooltip.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $WindowsDefenderTooltip.ForeColor  = $grayedColor
    
    $ExecutionPolicyTooltip             = New-Object system.Windows.Forms.Label
    $ExecutionPolicyTooltip.text        = "PowerShell: Set-ExecutionPolicy Unrestricted"
    $ExecutionPolicyTooltip.AutoSize    = $true
    $ExecutionPolicyTooltip.width       = 25
    $ExecutionPolicyTooltip.height      = 10
    $ExecutionPolicyTooltip.location    = New-Object System.Drawing.Point(15,85)
    $ExecutionPolicyTooltip.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ExecutionPolicyTooltip.ForeColor   = $grayedColor
    
    $RunningAsAdminTooltip              = New-Object system.Windows.Forms.Label
    $RunningAsAdminTooltip.text         = "Please run this script as Administrator"
    $RunningAsAdminTooltip.AutoSize     = $true
    $RunningAsAdminTooltip.width        = 25
    $RunningAsAdminTooltip.height       = 10
    $RunningAsAdminTooltip.location     = New-Object System.Drawing.Point(15,41)
    $RunningAsAdminTooltip.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $RunningAsAdminTooltip.ForeColor    = $grayedColor
    
    $EnoughHardStorageTooltip           = New-Object system.Windows.Forms.Label
    $EnoughHardStorageTooltip.text      = "Have at least 70GB of available storage"
    $EnoughHardStorageTooltip.AutoSize  = $true
    $EnoughHardStorageTooltip.width     = 25
    $EnoughHardStorageTooltip.height    = 10
    $EnoughHardStorageTooltip.location  = New-Object System.Drawing.Point(15,266)
    $EnoughHardStorageTooltip.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $EnoughHardStorageTooltip.ForeColor = $grayedColor

    ################################# Check Completion Controls #################################

    $BreakMyInstallCheckbox          = New-Object system.Windows.Forms.CheckBox
    $BreakMyInstallCheckbox.text     = "I understand that continuing without satisfying all"
    $BreakMyInstallCheckbox.AutoSize = $false
    $BreakMyInstallCheckbox.width    = 324
    $BreakMyInstallCheckbox.height   = 21
    $BreakMyInstallCheckbox.location = New-Object System.Drawing.Point(30,319)
    $BreakMyInstallCheckbox.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $BreakMyInstallCheckbox.Add_CheckStateChanged({
        if ($BreakMyInstallCheckbox.Checked) {
            $ChecksCompleteButton.enabled = $true
        } else {
            $ChecksCompleteButton.enabled = $false
        }
    })

    $BreakMyInstallLabel             = New-Object system.Windows.Forms.Label
    $BreakMyInstallLabel.text        = "pre-install checks might cause install issues"
    $BreakMyInstallLabel.AutoSize    = $true
    $BreakMyInstallLabel.width       = 25
    $BreakMyInstallLabel.height      = 10
    $BreakMyInstallLabel.location    = New-Object System.Drawing.Point(30,338)
    $BreakMyInstallLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ChecksCompleteButton            = New-Object system.Windows.Forms.Button
    $ChecksCompleteButton.text       = "Continue"
    $ChecksCompleteButton.width      = 97
    $ChecksCompleteButton.height     = 37
    $ChecksCompleteButton.enabled    = $false
    $ChecksCompleteButton.DialogResult   = [System.Windows.Forms.DialogResult]::OK
    $ChecksCompleteButton.location   = New-Object System.Drawing.Point(387,315)
    $ChecksCompleteButton.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
    $ChecksCompleteButton.Add_Click({
        $global:checksPassed = $true
        [void]$CommandoChecksManager.Close()
    })

    $InstallChecksGroup.controls.AddRange(@($ChecksPanel,$RunningAsAdminLabel,$ExecutionPolicyLabel,$WindowsDefenderLabel,$WindowsReleaseLabel,$RunningVMLabel,$RunningAsAdminTooltip,$ExecutionPolicyTooltip,$WindowsDefenderTooltip,$WindowsReleaseTooltip,$RunningVMTooltip,$EnoughHardStorageLabel, $EnoughHardStorageTooltip,$RunningAsAdmin,$EnoughHardStorage))
    $CommandoChecksManager.controls.AddRange(@($InstallChecksGroup,$ChecksCompleteButton,$BreakMyInstallCheckbox,$BreakMyInstallLabel))
    $ChecksPanel.controls.AddRange(@($RunningAsAdmin, $ExecutionPolicy,$WindowsDefender,$WindowsRelease,$RunningVM, $EnoughHardStorage))

    #################################################################################################
    ################################# Main Installer Form Controls ##################################
    #################################################################################################

    $CommandoInstaller               = New-Object system.Windows.Forms.Form
    $CommandoInstaller.ClientSize    = New-Object System.Drawing.Point(693,574)
    $CommandoInstaller.text          = "CommandoVM Installer"
    $CommandoInstaller.TopMost       = $true
    $CommandoInstaller.StartPosition = 'CenterScreen'
    $CommandoInstaller.Icon          = $icon

    $CommandoLogo                    = New-Object system.Windows.Forms.PictureBox
    $CommandoLogo.width              = 338
    $CommandoLogo.height             = 246
    $CommandoLogo.location           = New-Object System.Drawing.Point(179,37)
    $CommandoLogo.imageLocation      = Join-Path $PSScriptRoot "Images/commando.png"
    $CommandoLogo.SizeMode           = [System.Windows.Forms.PictureBoxSizeMode]::zoom

    ################################# Main Installer Profile Selection Controls #################################

    $ProfileSelector                 = New-Object system.Windows.Forms.ComboBox
    $ProfileSelector.text            = "Select Profile"
    $ProfileSelector.width           = 141
    $ProfileSelector.height          = 108
    $ProfileSelector.location        = New-Object System.Drawing.Point(380,449)
    $ProfileSelector.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ProfileSelector.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $ProfileSelector.Add_SelectedIndexChanged({
        $global:selectedProfile = $ProfileSelector.SelectedItem
    
        if ($ProfileSelector.SelectedItem -eq "Custom") {
            $RecommendedDiskSpaceLabel.Visible = $false
            $RecommendedDiskSpace.Visible = $false
        } else {
            # Find the DiskSize from $global:profileData where ProfileName equals $global:selectedProfile
            $diskSize = ($global:profileData | Where-Object { $_.ProfileName -eq $global:selectedProfile }).DiskSize
        
            # Set $RecommendedDiskSpace.Text to the found DiskSize
            $RecommendedDiskSpace.Text = "$($diskSize)GB"
            $RecommendedDiskSpaceLabel.Visible = $true
            $RecommendedDiskSpace.Visible = $true
        }
    })
    

    $ConfigureProfileButton          = New-Object system.Windows.Forms.Button
    $ConfigureProfileButton.text     = "Configure Profile"
    $ConfigureProfileButton.width    = 142
    $ConfigureProfileButton.height   = 29
    $ConfigureProfileButton.location  = New-Object System.Drawing.Point(380,478)
    $ConfigureProfileButton.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ConfigureProfileButton.Add_Click({Open-ProfileManager})

    $RecommendedDiskSpace            = New-Object system.Windows.Forms.Label
    $RecommendedDiskSpace.text       = "50GB+"
    $RecommendedDiskSpace.AutoSize   = $true
    $RecommendedDiskSpace.width      = 25
    $RecommendedDiskSpace.height     = 10
    $RecommendedDiskSpace.location   = New-Object System.Drawing.Point(590,523)
    $RecommendedDiskSpace.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $RecommendedDiskSpaceLabel       = New-Object system.Windows.Forms.Label
    $RecommendedDiskSpaceLabel.text  = "Recommended Disk Space - "
    $RecommendedDiskSpaceLabel.AutoSize  = $true
    $RecommendedDiskSpaceLabel.width  = 25
    $RecommendedDiskSpaceLabel.height  = 10
    $RecommendedDiskSpaceLabel.location  = New-Object System.Drawing.Point(390,523)
    $RecommendedDiskSpaceLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    $RecommendedDiskSpaceLabel.ForeColor  = [System.Drawing.ColorTranslator]::FromHtml("#c10000")

    ################################# Main Installer Profile Labels #################################

    $ProfileLabels                   = New-Object system.Windows.Forms.Groupbox
    $ProfileLabels.height            = 166
    $ProfileLabels.width             = 304
    $ProfileLabels.text              = "Available Profiles"
    $ProfileLabels.location          = New-Object System.Drawing.Point(38,342)

    $ProfileLabelDefault             = New-Object system.Windows.Forms.Label
    $ProfileLabelDefault.text        = "Default"
    $ProfileLabelDefault.AutoSize    = $true
    $ProfileLabelDefault.width       = 25
    $ProfileLabelDefault.height      = 10
    $ProfileLabelDefault.location    = New-Object System.Drawing.Point(20,25)
    $ProfileLabelDefault.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $ProfileLabelFull                = New-Object system.Windows.Forms.Label
    $ProfileLabelFull.text           = "Full"
    $ProfileLabelFull.AutoSize       = $true
    $ProfileLabelFull.width          = 25
    $ProfileLabelFull.height         = 10
    $ProfileLabelFull.location       = New-Object System.Drawing.Point(20,50)
    $ProfileLabelFull.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $ProfileLabelLite                = New-Object system.Windows.Forms.Label
    $ProfileLabelLite.text           = "Lite"
    $ProfileLabelLite.AutoSize       = $true
    $ProfileLabelLite.width          = 25
    $ProfileLabelLite.height         = 10
    $ProfileLabelLite.location       = New-Object System.Drawing.Point(20,75)
    $ProfileLabelLite.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $ProfileLabelDeveloper           = New-Object system.Windows.Forms.Label
    $ProfileLabelDeveloper.text      = "Developer"
    $ProfileLabelDeveloper.AutoSize  = $true
    $ProfileLabelDeveloper.width     = 25
    $ProfileLabelDeveloper.height    = 10
    $ProfileLabelDeveloper.location  = New-Object System.Drawing.Point(20,100)
    $ProfileLabelDeveloper.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $ProfileLabelVictim              = New-Object system.Windows.Forms.Label
    $ProfileLabelVictim.text         = "Victim"
    $ProfileLabelVictim.AutoSize     = $true
    $ProfileLabelVictim.width        = 25
    $ProfileLabelVictim.height       = 10
    $ProfileLabelVictim.location     = New-Object System.Drawing.Point(20,125)
    $ProfileLabelVictim.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    ################################# Main Installer Profile Description Labels #################################

    $ProfileLabelDescriptionDefault   = New-Object system.Windows.Forms.Label
    $ProfileLabelDescriptionDefault.text  = "- numerous packages for pentesting"
    $ProfileLabelDescriptionDefault.AutoSize  = $true
    $ProfileLabelDescriptionDefault.width  = 25
    $ProfileLabelDescriptionDefault.height  = 10
    $ProfileLabelDescriptionDefault.location  = New-Object System.Drawing.Point(70,25)
    $ProfileLabelDescriptionDefault.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ProfileLabelDescriptionFull     = New-Object system.Windows.Forms.Label
    $ProfileLabelDescriptionFull.text  = "- all tools suitable for CommandoVM"
    $ProfileLabelDescriptionFull.AutoSize  = $true
    $ProfileLabelDescriptionFull.width  = 25
    $ProfileLabelDescriptionFull.height  = 10
    $ProfileLabelDescriptionFull.location  = New-Object System.Drawing.Point(50,50)
    $ProfileLabelDescriptionFull.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ProfileLabelDescriptionLite     = New-Object system.Windows.Forms.Label
    $ProfileLabelDescriptionLite.text  = "- only the bare minimum essential tools"
    $ProfileLabelDescriptionLite.AutoSize  = $true
    $ProfileLabelDescriptionLite.width  = 25
    $ProfileLabelDescriptionLite.height  = 10
    $ProfileLabelDescriptionLite.location  = New-Object System.Drawing.Point(50,75)
    $ProfileLabelDescriptionLite.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ProfileLabelDescriptionDeveloper   = New-Object system.Windows.Forms.Label
    $ProfileLabelDescriptionDeveloper.text  = "- malware development tooling"
    $ProfileLabelDescriptionDeveloper.text  = "- malware development tooling"
    $ProfileLabelDescriptionDeveloper.text  = "- malware development tooling"
    $ProfileLabelDescriptionDeveloper.AutoSize  = $true
    $ProfileLabelDescriptionDeveloper.width  = 25
    $ProfileLabelDescriptionDeveloper.height  = 10
    $ProfileLabelDescriptionDeveloper.location  = New-Object System.Drawing.Point(90,100)
    $ProfileLabelDescriptionDeveloper.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ProfileLabelDescriptionVictim   = New-Object system.Windows.Forms.Label
    $ProfileLabelDescriptionVictim.text  = "- set up with tools for payload testing"
    $ProfileLabelDescriptionVictim.AutoSize  = $true
    $ProfileLabelDescriptionVictim.width  = 25
    $ProfileLabelDescriptionVictim.height  = 10
    $ProfileLabelDescriptionVictim.location  = New-Object System.Drawing.Point(65,125)
    $ProfileLabelDescriptionVictim.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    ################################# Main Installer License Labels #################################

    $DisclaimerLabelLine1            = New-Object system.Windows.Forms.Label
    $DisclaimerLabelLine1.text       = "By proceeding with the installation, you are"
    $DisclaimerLabelLine1.AutoSize   = $true
    $DisclaimerLabelLine1.width      = 262
    $DisclaimerLabelLine1.height     = 12
    $DisclaimerLabelLine1.location   = New-Object System.Drawing.Point(380,344)
    $DisclaimerLabelLine1.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $DisclaimerLabelLine2            = New-Object system.Windows.Forms.Label
    $DisclaimerLabelLine2.text       = "accepting the license terms of each package,"
    $DisclaimerLabelLine2.AutoSize   = $true
    $DisclaimerLabelLine2.width      = 262
    $DisclaimerLabelLine2.height     = 10
    $DisclaimerLabelLine2.location   = New-Object System.Drawing.Point(380,368)
    $DisclaimerLabelLine2.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $DisclaimerLabelLine3            = New-Object system.Windows.Forms.Label
    $DisclaimerLabelLine3.text       = "and acknowledging that your use of each package"
    $DisclaimerLabelLine3.AutoSize   = $true
    $DisclaimerLabelLine3.width      = 262
    $DisclaimerLabelLine3.height     = 10
    $DisclaimerLabelLine3.location   = New-Object System.Drawing.Point(380,392)
    $DisclaimerLabelLine3.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $DisclaimerLabelLine4            = New-Object system.Windows.Forms.Label
    $DisclaimerLabelLine4.text       = " will be subject to its respective license terms."
    $DisclaimerLabelLine4.AutoSize   = $true
    $DisclaimerLabelLine4.width      = 262
    $DisclaimerLabelLine4.height     = 10
    $DisclaimerLabelLine4.location   = New-Object System.Drawing.Point(380,417)
    $DisclaimerLabelLine4.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    ################################# Main Installer Controls #################################

    $InstallButton                   = New-Object system.Windows.Forms.Button
    $InstallButton.text              = "Install"
    $InstallButton.width             = 104
    $InstallButton.height            = 60
    $InstallButton.location          = New-Object System.Drawing.Point(548,446)
    $InstallButton.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
    $InstallButton.Add_Click({
        if (Open-PasswordEntry) {
            [void]$CommandoInstaller.Close()
		    [void]$CommandoInstaller.Dispose()
            Install-Profile -ProfileName $global:selectedProfile
        }
    })

    $CommandoInstaller.controls.AddRange(@($CommandoLogo,$InstallButton,$ProfileSelector,$ConfigureProfileButton,$ProfileLabels,$RecommendedDiskSpaceLabel,$DisclaimerLabelLine1,$DisclaimerLabelLine2,$DisclaimerLabelLine3,$DisclaimerLabelLine4,$RecommendedDiskSpace))
    $ProfileLabels.controls.AddRange(@($ProfileLabelDescriptionLite,$Label1,$ProfileLabelLite,$ProfileLabelFull,$ProfileLabelDescriptionFull,$ProfileLabelDefault,$ProfileLabelDescriptionDefault,$ProfileLabelDeveloper,$ProfileLabelDescriptionDeveloper,$ProfileLabelVictim,$ProfileLabelDescriptionVictim))

    #################################################################################################
    ################################# Profile Manager Form Controls #################################
    #################################################################################################

    $CommandoProfileManager          = New-Object system.Windows.Forms.Form
    $CommandoProfileManager.ClientSize  = New-Object System.Drawing.Point(660,651)
    $CommandoProfileManager.text     = "CommandoVM Profile Manager"
    $CommandoProfileManager.TopMost  = $true
    $CommandoProfileManager.StartPosition = 'CenterScreen'
    $CommandoProfileManager.Icon     = $icon

    ################################# Profile Manager Preset Selector Controls #################################

    $PresetSelector                  = New-Object system.Windows.Forms.ComboBox
    $PresetSelector.text             = "Default"
    $PresetSelector.width            = 122
    $PresetSelector.height           = 20
    $PresetSelector.location         = New-Object System.Drawing.Point(252,11)
    $PresetSelector.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $PresetSelector.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $PresetSelector.Add_SelectedIndexChanged({Set-ProfilePreset -ProfileName $PresetSelector.SelectedItem})

    $PresetSelectorLabel             = New-Object system.Windows.Forms.Label
    $PresetSelectorLabel.text        = "Preset"
    $PresetSelectorLabel.AutoSize    = $true
    $PresetSelectorLabel.width       = 25
    $PresetSelectorLabel.height      = 10
    $PresetSelectorLabel.location    = New-Object System.Drawing.Point(203,14)
    $PresetSelectorLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    ################################# Profile Manager Package Installation Controls #################################

    $SelectedPackagesList            = New-Object system.Windows.Forms.ListBox
    $SelectedPackagesList.text       = "listBox"
    $SelectedPackagesList.width      = 232
    $SelectedPackagesList.height     = 266
    $SelectedPackagesList.location   = New-Object System.Drawing.Point(16,69)
    $SelectedPackagesList.Add_SelectedIndexChanged({
        # We're only gonna reset the available package selection if we have a selection in this listbox
        if ($SelectedPackagesList.SelectedIndex -ne -1) { 
            Set-PackageInformation -PackageName $SelectedPackagesList.SelectedItem
            $AvailablePackagesList.ClearSelected() 
        }
    })

    $AvailablePackagesList           = New-Object system.Windows.Forms.ListBox
    $AvailablePackagesList.text      = "listBox"
    $AvailablePackagesList.width     = 228
    $AvailablePackagesList.height    = 265
    $AvailablePackagesList.location  = New-Object System.Drawing.Point(318,69)
    $AvailablePackagesList.Add_SelectedIndexChanged({
        # We're only gonna reset the selected package selection if we have a selection in this listbox
        if ($AvailablePackagesList.SelectedIndex -ne -1) {
            Set-PackageInformation -PackageName $AvailablePackagesList.SelectedItem
            $SelectedPackagesList.ClearSelected()
        }
    })

    $SelectedPackagesLabel           = New-Object system.Windows.Forms.Label
    $SelectedPackagesLabel.text      = "Selected Packages"
    $SelectedPackagesLabel.AutoSize  = $true
    $SelectedPackagesLabel.width     = 25
    $SelectedPackagesLabel.height    = 10
    $SelectedPackagesLabel.location  = New-Object System.Drawing.Point(64,42)
    $SelectedPackagesLabel.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

    $AvailablePackagesLabel          = New-Object system.Windows.Forms.Label
    $AvailablePackagesLabel.text     = "Available Packages"
    $AvailablePackagesLabel.AutoSize  = $true
    $AvailablePackagesLabel.width    = 25
    $AvailablePackagesLabel.height   = 10
    $AvailablePackagesLabel.location  = New-Object System.Drawing.Point(360,42)
    $AvailablePackagesLabel.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

    ################################# Profile Manager Package Addition Controls #################################

    $PackageInstallationGroup        = New-Object system.Windows.Forms.Groupbox
    $PackageInstallationGroup.height = 367
    $PackageInstallationGroup.width  = 563
    $PackageInstallationGroup.text   = "Package Installation"
    $PackageInstallationGroup.location  = New-Object System.Drawing.Point(48,37)

    $AddPackageButton                = New-Object system.Windows.Forms.Button
    $AddPackageButton.text           = "<"
    $AddPackageButton.width          = 43
    $AddPackageButton.height         = 30
    $AddPackageButton.location       = New-Object System.Drawing.Point(260,103)
    $AddPackageButton.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $AddPackageButton.Add_Click({Add-SelectedPackage})

    $AddAllPackagesButton            = New-Object system.Windows.Forms.Button
    $AddAllPackagesButton.text       = "<<"
    $AddAllPackagesButton.width      = 43
    $AddAllPackagesButton.height     = 30
    $AddAllPackagesButton.location   = New-Object System.Drawing.Point(260,147)
    $AddAllPackagesButton.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $AddAllPackagesButton.Add_Click({Add-AllPackages})

    $RemovePackageButton             = New-Object system.Windows.Forms.Button
    $RemovePackageButton.text        = ">"
    $RemovePackageButton.width       = 43
    $RemovePackageButton.height      = 30
    $RemovePackageButton.location    = New-Object System.Drawing.Point(260,207)
    $RemovePackageButton.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $RemovePackageButton.Add_Click({Remove-SelectedPackage})

    $RemoveAllPackagesButton         = New-Object system.Windows.Forms.Button
    $RemoveAllPackagesButton.text    = ">>"
    $RemoveAllPackagesButton.width   = 43
    $RemoveAllPackagesButton.height  = 30
    $RemoveAllPackagesButton.location  = New-Object System.Drawing.Point(260,254)
    $RemoveAllPackagesButton.Font    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $RemoveAllPackagesButton.Add_Click({Remove-AllPackages})

    $AddChocoPackageButton               = New-Object system.Windows.Forms.Button
    $AddChocoPackageButton.text          = "Add Choco Package"
    $AddChocoPackageButton.width         = 150
    $AddChocoPackageButton.height        = 25
    $AddChocoPackageButton.location      = New-Object System.Drawing.Point(396,336)
    $AddChocoPackageButton.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $AddChocoPackageButton.Add_Click({Open-AddChocoPackage})

    ################################# Profile Manager Package Count Labels #################################

    $SelectedCountLabel              = New-Object system.Windows.Forms.Label
    $SelectedCountLabel.text         = "Total:"
    $SelectedCountLabel.AutoSize     = $true
    $SelectedCountLabel.width        = 25
    $SelectedCountLabel.height       = 10
    $SelectedCountLabel.location     = New-Object System.Drawing.Point(15,342)
    $SelectedCountLabel.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

    $AvailableCountLabel             = New-Object system.Windows.Forms.Label
    $AvailableCountLabel.text        = "Total:"
    $AvailableCountLabel.AutoSize    = $true
    $AvailableCountLabel.width       = 25
    $AvailableCountLabel.height      = 10
    $AvailableCountLabel.location    = New-Object System.Drawing.Point(316,340)
    $AvailableCountLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',8)

    ################################# Profile Manager Package Information Controls #################################

    $PackageInformationGroup         = New-Object system.Windows.Forms.Groupbox
    $PackageInformationGroup.height  = 168
    $PackageInformationGroup.width   = 562
    $PackageInformationGroup.text    = "Package Information"
    $PackageInformationGroup.location  = New-Object System.Drawing.Point(48,424)

    $Authors                         = New-Object system.Windows.Forms.Label
    $Authors.text                    = "Authors"
    $Authors.AutoSize                = $false
    $Authors.AutoEllipsis            = $true
    $Authors.width                   = 450
    $Authors.height                  = 20
    $Authors.location                = New-Object System.Drawing.Point(70,25)
    $Authors.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Version                         = New-Object system.Windows.Forms.Label
    $Version.text                    = "Version"
    $Version.AutoSize                = $true
    $Version.width                   = 25
    $Version.height                  = 10
    $Version.location                = New-Object System.Drawing.Point(70,50)
    $Version.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $Description                     = New-Object system.Windows.Forms.Label
    $Description.text                = "Tool Description"
    $Description.AutoSize            = $false
    $Description.width               = 529
    $Description.height              = 50
    $Description.location            = New-Object System.Drawing.Point(10,100)
    $Description.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $AuthorsLabel                    = New-Object system.Windows.Forms.Label
    $AuthorsLabel.text               = "Authors:"
    $AuthorsLabel.AutoSize           = $true
    $AuthorsLabel.width              = 25
    $AuthorsLabel.height             = 10
    $AuthorsLabel.location           = New-Object System.Drawing.Point(10,25)
    $AuthorsLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $VersionLabel                    = New-Object system.Windows.Forms.Label
    $VersionLabel.text               = "Version:"
    $VersionLabel.AutoSize           = $true
    $VersionLabel.width              = 25
    $VersionLabel.height             = 10
    $VersionLabel.location           = New-Object System.Drawing.Point(10,50)
    $VersionLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $DescriptionLabel                = New-Object system.Windows.Forms.Label
    $DescriptionLabel.text           = "Tool Description"
    $DescriptionLabel.AutoSize       = $true
    $DescriptionLabel.width          = 25
    $DescriptionLabel.height         = 10
    $DescriptionLabel.location       = New-Object System.Drawing.Point(10,75)
    $DescriptionLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    ################################# Profile Manager Buttons #################################

    $DoneButton                      = New-Object system.Windows.Forms.Button
    $DoneButton.text                 = "Done"
    $DoneButton.width                = 94
    $DoneButton.height               = 30
    $DoneButton.location             = New-Object System.Drawing.Point(424,604)
    $DoneButton.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $DoneButton.Add_Click({
        Save-Profile
    
        # Check if "Custom" exists in $ProfileSelector.Items, and add it if it doesn't
        if ("Custom" -notin $ProfileSelector.Items) {
            $ProfileSelector.Items.Add("Custom")
        }
    
        # Set $ProfileSelector.Text to "Custom"
        $ProfileSelector.Text = "Custom"
    
        [void]$CommandoProfileManager.Close()
    })
    

    $SaveProfileButton               = New-Object system.Windows.Forms.Button
    $SaveProfileButton.text          = "Save Profile As"
    $SaveProfileButton.width         = 124
    $SaveProfileButton.height        = 30
    $SaveProfileButton.location      = New-Object System.Drawing.Point(115,604)
    $SaveProfileButton.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $SaveProfileButton.Add_Click({Save-ProfileAs})

    $ResetProfileButton              = New-Object system.Windows.Forms.Button
    $ResetProfileButton.text         = "Reset Profile"
    $ResetProfileButton.width        = 127
    $ResetProfileButton.height       = 30
    $ResetProfileButton.location     = New-Object System.Drawing.Point(269,604)
    $ResetProfileButton.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ResetProfileButton.Add_Click({Set-ProfilePreset -ProfileName $selectedProfile})

    ################################# Profile Manager Form Constructor #################################

    $CommandoProfileManager.controls.AddRange(@($PackageInstallationGroup,$DoneButton,$SaveProfileButton,$ResetProfileButton,$PackageInformationGroup))
    $PackageInstallationGroup.controls.AddRange(@($SelectedPackagesLabel,$PresetSelectorLabel,$AddPackageButton,$AddAllPackagesButton,$RemovePackageButton,$RemoveAllPackagesButton,$PresetSelector,$AvailablePackagesLabel,$availableCountLabel,$selectedCountLabel,$SelectedPackagesList,$AvailablePackagesList,$AddChocoPackageButton))
    $PackageInformationGroup.controls.AddRange(@($AuthorsLabel,$Description,$DescriptionLabel,$VersionLabel,$Authors,$Version))

    #################################################################################################
    ################################# Password Entry Form Controls ##################################
    #################################################################################################

    $CommandoPasswordManager         = New-Object system.Windows.Forms.Form
    $CommandoPasswordManager.ClientSize  = New-Object System.Drawing.Point(400,270)
    $CommandoPasswordManager.text    = "CommandoVM Boxstarter Password"
    $CommandoPasswordManager.TopMost  = $true
    $CommandoPasswordManager.Icon      = $icon
    $CommandoPasswordManager.StartPosition = 'CenterScreen'

    $PasswordOKButton                = New-Object system.Windows.Forms.Button
    $PasswordOKButton.text           = "OK"
    $PasswordOKButton.DialogResult   = [System.Windows.Forms.DialogResult]::OK
    $PasswordOKButton.width          = 95
    $PasswordOKButton.height         = 28
    $PasswordOKButton.location       = New-Object System.Drawing.Point(153,230)
    $PasswordOKButton.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $PasswordInfoLabel               = New-Object system.Windows.Forms.Label
    $PasswordInfoLabel.text          = "Boxstarter requires user credentials to automatically login and continue the install on a reboot. `n`nIf you do not have a password set, leave the field blank"
    $PasswordInfoLabel.AutoSize      = $true
    $PasswordInfoLabel.Visible       = $false
    $PasswordInfoLabel.MaximumSize   = New-Object System.Drawing.Size(350, 0)
    $PasswordInfoLabel.location      = New-Object System.Drawing.Point(11,46)
    $PasswordInfoLabel.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $PasswordInfoHeadingLabel        = New-Object system.Windows.Forms.Label
    $PasswordInfoHeadingLabel.text   = "Why is my password required?"
    $PasswordInfoHeadingLabel.AutoSize  = $true
    $PasswordInfoHeadingLabel.width  = 25
    $PasswordInfoHeadingLabel.height  = 10
    $PasswordInfoHeadingLabel.location  = New-Object System.Drawing.Point(11,19)
    $PasswordInfoHeadingLabel.Font   = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

    $PasswordInfoBoxstarterLabel     = New-Object system.Windows.Forms.Label
    $PasswordInfoBoxstarterLabel.text  = "Learn more at:"
    $PasswordInfoBoxstarterLabel.AutoSize  = $true
    $PasswordInfoBoxstarterLabel.width  = 25
    $PasswordInfoBoxstarterLabel.height  = 10
    $PasswordInfoBoxstarterLabel.location  = New-Object System.Drawing.Point(11,117)
    $PasswordInfoBoxstarterLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $PasswordInfoBoxstarterLinkLabel   = New-Object system.Windows.Forms.Label
    $PasswordInfoBoxstarterLinkLabel.text  = "https://boxstarter.org/installingpackages"
    $PasswordInfoBoxstarterLinkLabel.AutoSize  = $true
    $PasswordInfoBoxstarterLinkLabel.width  = 25
    $PasswordInfoBoxstarterLinkLabel.height  = 10
    $PasswordInfoBoxstarterLinkLabel.location  = New-Object System.Drawing.Point(104,117)
    $PasswordInfoBoxstarterLinkLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))

    $PasswordTextBox                 = New-Object system.Windows.Forms.TextBox
    $PasswordTextBox.multiline       = $false
    $PasswordTextBox.width           = 226
    $PasswordTextBox.height          = 20
    $PasswordTextBox.UseSystemPasswordChar = $True
    $PasswordTextBox.location        = New-Object System.Drawing.Point(89,195)
    $PasswordTextBox.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',14)

    $PasswordEntryLabel              = New-Object system.Windows.Forms.Label
    $PasswordEntryLabel.text         = "Enter your user password:"
    $PasswordEntryLabel.AutoSize     = $true
    $PasswordEntryLabel.width        = 25
    $PasswordEntryLabel.height       = 10
    $PasswordEntryLabel.location     = New-Object System.Drawing.Point(124,171)
    $PasswordEntryLabel.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $PasswordInfoGroup               = New-Object system.Windows.Forms.Groupbox
    $PasswordInfoGroup.height        = 145
    $PasswordInfoGroup.width         = 380
    $PasswordInfoGroup.text          = "About"
    $PasswordInfoGroup.location      = New-Object System.Drawing.Point(10,17)

    $CommandoPasswordManager.controls.AddRange(@($PasswordOKButton,$PasswordTextBox,$PasswordEntryLabel,$PasswordInfoGroup))
    $PasswordInfoGroup.controls.AddRange(@($PasswordInfoLabel,$PasswordInfoHeadingLabel,$PasswordInfoBoxstarterLabel,$PasswordInfoBoxstarterLinkLabel))

    #################################################################################################
    ################################# Chocolatey Package Dialog Box #################################
    #################################################################################################

    $CommandoChocoManager                            = New-Object system.Windows.Forms.Form
    $CommandoChocoManager.ClientSize                 = New-Object System.Drawing.Point(407,287)
    $CommandoChocoManager.text                       = "CommandoVM Chocolatey Package"
    $CommandoChocoManager.TopMost                    = $true
    $CommandoChocoManager.Icon      = $icon
    $CommandoChocoManager.StartPosition              = 'CenterScreen'
    
    $ChocoPackageTextBox                        = New-Object system.Windows.Forms.TextBox
    $ChocoPackageTextBox.multiline              = $false
    $ChocoPackageTextBox.width                  = 231
    $ChocoPackageTextBox.height                 = 20
    $ChocoPackageTextBox.location               = New-Object System.Drawing.Point(19,185)
    $ChocoPackageTextBox.Font                   = New-Object System.Drawing.Font('Microsoft Sans Serif',14)
    
    $ChocoAboutGroup                       = New-Object system.Windows.Forms.Groupbox
    $ChocoAboutGroup.height                = 118
    $ChocoAboutGroup.width                 = 368
    $ChocoAboutGroup.text                  = "About"
    $ChocoAboutGroup.location              = New-Object System.Drawing.Point(19,22)
    
    $ChocoPackageErrorLabel                          = New-Object system.Windows.Forms.Label
    $ChocoPackageErrorLabel.text                     = "Chocolatey package not found"
    $ChocoPackageErrorLabel.AutoSize                 = $true
    $ChocoPackageErrorLabel.visible                  = $false
    $ChocoPackageErrorLabel.width                    = 25
    $ChocoPackageErrorLabel.height                   = 10
    $ChocoPackageErrorLabel.location                 = New-Object System.Drawing.Point(115,216)
    $ChocoPackageErrorLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $ChocoPackageLabel                          = New-Object system.Windows.Forms.Label
    $ChocoPackageLabel.text                     = "Enter Chocolatey package name:"
    $ChocoPackageLabel.AutoSize                 = $true
    $ChocoPackageLabel.width                    = 25
    $ChocoPackageLabel.height                   = 10
    $ChocoPackageLabel.location                 = New-Object System.Drawing.Point(19,157)
    $ChocoPackageLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $ChocoAboutHeadingLabel                          = New-Object system.Windows.Forms.Label
    $ChocoAboutHeadingLabel.text                     = "Adding Chocolatey Packages"
    $ChocoAboutHeadingLabel.AutoSize                 = $true
    $ChocoAboutHeadingLabel.width                    = 25
    $ChocoAboutHeadingLabel.height                   = 10
    $ChocoAboutHeadingLabel.location                 = New-Object System.Drawing.Point(4,17)
    $ChocoAboutHeadingLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',12,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
    
    $ChocoAboutLabel                          = New-Object system.Windows.Forms.Label
    $ChocoAboutLabel.text                     = "CommandoVM uses Chocolatey to install profile packages. You can add any package available in the Chocolatey Community Package Repository to the Commando install. "
    $ChocoAboutLabel.AutoSize                 = $true
    $ChocoAboutLabel.MaximumSize              = New-Object System.Drawing.Size(370, 0)
    $ChocoAboutLabel.location                 = New-Object System.Drawing.Point(4,42)
    $ChocoAboutLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $ChocoLearnMoreLabel                          = New-Object system.Windows.Forms.Label
    $ChocoLearnMoreLabel.text                     = "Learn More at:"
    $ChocoLearnMoreLabel.AutoSize                 = $true
    $ChocoLearnMoreLabel.width                    = 25
    $ChocoLearnMoreLabel.height                   = 10
    $ChocoLearnMoreLabel.location                 = New-Object System.Drawing.Point(4,93)
    $ChocoLearnMoreLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    
    $ChocoLinkLabel                          = New-Object system.Windows.Forms.Label
    $ChocoLinkLabel.text                     = "https://community.chocolatey.org/packages"
    $ChocoLinkLabel.AutoSize                 = $true
    $ChocoLinkLabel.width                    = 25
    $ChocoLinkLabel.height                   = 10
    $ChocoLinkLabel.location                 = New-Object System.Drawing.Point(95,93)
    $ChocoLinkLabel.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Underline))    

    $ChocoAddPackageButton                         = New-Object system.Windows.Forms.Button
    $ChocoAddPackageButton.text                    = "Add Package"
    $ChocoAddPackageButton.DialogResult            = [System.Windows.Forms.DialogResult]::OK
    $ChocoAddPackageButton.width                   = 118
    $ChocoAddPackageButton.height                  = 30
    $ChocoAddPackageButton.enabled                 = $false
    $ChocoAddPackageButton.location                = New-Object System.Drawing.Point(144,238)
    $ChocoAddPackageButton.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

    $ChocoFindPackageButton          = New-Object system.Windows.Forms.Button
    $ChocoFindPackageButton.text     = "Find Package"
    $ChocoFindPackageButton.width    = 118
    $ChocoFindPackageButton.height   = 30
    $ChocoFindPackageButton.enabled   = $true
    $ChocoFindPackageButton.location  = New-Object System.Drawing.Point(269,185)
    $ChocoFindPackageButton.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
    $ChocoFindPackageButton.Add_Click({
        if (Get-ChocoPackage -PackageName $ChocoPackageTextBox.Text) {
            $ChocoPackageErrorLabel.Text = "Found Chocolatey package"
            $ChocoPackageErrorLabel.ForeColor = $successColor
            $ChocoPackageErrorLabel.Visible = $true
            $ChocoAddPackageButton.Enabled = $true
        } else {
            $ChocoPackageErrorLabel.text = "Chocolatey package not found"
            $ChocoPackageErrorLabel.ForeColor = $errorColor
            $ChocoPackageErrorLabel.Visible = $true
            $ChocoAddPackageButton.Enabled = $false
        }
    })

    $CommandoChocoManager.controls.AddRange(@($ChocoPackageTextBox,$ChocoAddPackageButton,$ChocoAboutGroup,$ChocoPackageErrorLabel,$ChocoPackageLabel,$ChocoFindPackageButton))
    $ChocoAboutGroup.controls.AddRange(@($ChocoAboutHeadingLabel,$ChocoAboutLabel,$ChocoLearnMoreLabel,$ChocoLinkLabel))
}

#################################################################################################
#################################################################################################
###################################### Installer Functions ######################################
#################################################################################################
#################################################################################################

################################# Functions that conduct Pre-Install Checks #################################

function Check-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-Not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $false
    } else {
        return $true
    }
}
function Check-ExecutionPolicy {
    if ((Get-ExecutionPolicy).ToString() -ne "Unrestricted") {
        return $false
    } else {
        return $true
    }
}
function Check-DefenderAndTamperProtection {
    $defender = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpPreference
    if ($defender.DisableRealtimeMonitoring) {
        if (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ea 0) {
            if ($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection").TamperProtection -eq 5) {
                return $false
            } else {
                return $true
            }
        }
    } else {
        return $false
    }
}
function Check-SupportedOS {
    $osVersion = (Get-WmiObject -class Win32_OperatingSystem).BuildNumber
    $testedVersions = @(19045, 22621)
    if ($osVersion -notin $testedVersions) {
        return $false
    } else {
        return $true
    }
}
function Check-VM {
    $virtualModels = @('VirtualBox', 'VMware', 'Virtual Machine', 'Hyper-V')
    $computerSystemModel = (Get-WmiObject win32_computersystem).model
    $isVirtualModel = $false
    
    foreach ($model in $virtualModels) {
        if ($computerSystemModel.Contains($model)) {
            $isVirtualModel = $true
            break
        }
    }

    if (!$isVirtualModel) {
        return $false
    } else {
        return $true
    }
}
function Check-Storage {
    $disk = Get-PSDrive (Get-Location).Drive.Name
    Start-Sleep -Seconds 1
    if (($disk.used + $disk.free)/1GB -gt 68.8) {
        return $true
    } else {
        return $false
    }
}

################################# Functions that change pre-install check configs #################################

function Check-ChocoBoxstarterVersions {
    $boxstarterVersionGood = $false
    $chocolateyVersionGood = $false
    if(${Env:ChocolateyInstall} -and (Test-Path "${Env:ChocolateyInstall}\bin\choco.exe")) {
        $chocoVersion = choco --version
        $chocolateyVersionGood = [System.Version]$chocoVersion -ge [System.Version]"0.10.13"
        choco info -l -r "boxstarter" | ForEach-Object { $name, $chocoVersion = $_ -split '\|' }
        $boxstarterVersionGood = [System.Version]$chocoVersion -ge [System.Version]"3.0.0"
        if ($chocolateyVersionGood -and $boxstarterVersionGood) {
            return $true
        } else {
            return $false
        }
    } else {
        return $false
    }
}

function Check-ChocoBoxstarterInstalls {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1'))
    Get-Boxstarter -Force

    # Fix verbosity issues with Boxstarter v3
    # See: https://github.com/chocolatey/boxstarter/issues/501
    $fileToFix = "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\Chocolatey.ps1"
    $offendingString = 'if ($val -is [string] -or $val -is [boolean]) {'
    if ((Get-Content $fileToFix -raw) -contains $offendingString) {
        $fixString = 'if ($val -is [string] -or $val -is [boolean] -or $val -is [system.management.automation.actionpreference]) {'
        ((Get-Content $fileToFix -raw) -replace [regex]::escape($offendingString),$fixString) | Set-Content $fileToFix
    }
    $fileToFix = "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\invoke-chocolatey.ps1"
    $offendingString = 'Verbose           = $VerbosePreference'
    if ((Get-Content $fileToFix -raw) -contains $offendingString) {
        $fixString = 'Verbose           = ($global:VerbosePreference -eq "Continue")'
        ((Get-Content $fileToFix -raw) -replace [regex]::escape($offendingString),$fixString) | Set-Content $fileToFix
    }
}
function Check-BoxstarterConfig {
    $Boxstarter.RebootOk = (-not $noReboots.IsPresent)
    $Boxstarter.AutoLogin = $true
    $Boxstarter.SuppressLogging = $True
    $global:VerbosePreference = "SilentlyContinue"
    Set-BoxstarterConfig -NugetSources "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://chocolatey.org/api/v2"
    Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowFullPathInTitleBar
}

function Check-ChocoConfig {
    choco sources add -n="vm-packages" -s "$desktopPath;.;https://www.myget.org/F/vm-packages/api/v2;https://myget.org/F/vm-packages/api/v2" --priority 1
    choco feature enable -n allowGlobalConfirmation
    choco feature enable -n allowEmptyChecksums
    $cache = "${Env:LocalAppData}\ChocoCache"
    New-Item -Path $cache -ItemType directory -Force | Out-Null
    choco config set cacheLocation $cache
}

function Check-PowerOptions {
    powercfg -change -monitor-timeout-ac 0 | Out-Null
    powercfg -change -monitor-timeout-dc 0 | Out-Null
    powercfg -change -disk-timeout-ac 0 | Out-Null
    powercfg -change -disk-timeout-dc 0 | Out-Null
    powercfg -change -standby-timeout-ac 0 | Out-Null
    powercfg -change -standby-timeout-dc 0 | Out-Null
    powercfg -change -hibernate-timeout-ac 0 | Out-Null
    powercfg -change -hibernate-timeout-dc 0 | Out-Null
}

################################# Functions that Get Profiles and Packages #################################

function Get-ProfileData {
    $profilesFolder = Join-Path $PSScriptRoot "./Profiles/"
    $profiles = @()

    # Loop over the profiles folder
    Get-ChildItem -Path $profilesFolder -Filter "*.xml" | ForEach-Object {
        $xmlContent = [xml](Get-Content $_.FullName)
        $profileName = $_.BaseName
        $diskSize = $xmlContent.config.envs.env | Where-Object { $_.name -eq "MIN_DISK_SPACE" } | Select-Object -ExpandProperty value

        # Write the profile metadata to a variable
        $profiles += [PSCustomObject]@{
            ProfileName = $profileName
            DiskSize    = $diskSize
            XmlPath     = $_.FullName
        }
    }

    return $profiles
}

function Get-PackagesFromProfile {
    param (
        [string]$ProfileName
    )

    # Get the XML profile path for the specified profile
    $profilePath = $global:profileData | Where-Object { $_.ProfileName -eq $ProfileName } | Select-Object -ExpandProperty XmlPath

    # Read the XML profile and pull the package names out
    if ($profilePath) {
        $xmlContent = [xml](Get-Content $profilePath)
        $packages = $xmlContent.config.packages.package
        return $packages
    }
    else {
        Write-Host "[!] Profile not found." -ForegroundColor Red
        return @()
    }
}

function Get-AvailablePackages {
    $apiUrl = "https://www.myget.org/F/vm-packages/Packages"
    $destination = Join-Path $PSScriptRoot "./available_packages.xml"
    $blockList = @("flarevm.installer.vm", "common.vm")

    $packages = @()

    # Define XML namespaces
    $nsManager = New-Object -TypeName "System.Xml.XmlNamespaceManager" -ArgumentList (New-Object System.Xml.XmlDocument).NameTable
    $nsManager.AddNamespace("atom", "http://www.w3.org/2005/Atom")
    $nsManager.AddNamespace("d", "http://schemas.microsoft.com/ado/2007/08/dataservices")
    $nsManager.AddNamespace("m", "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata")

    do {
        # Download the XML from MyGet API
        try {
            Invoke-WebRequest -Uri $apiUrl -OutFile $destination -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to download available_packages.xml. Error: $_"
            exit
        }

        # Load the XML content
        $xmlContent = [xml](Get-Content $destination)

        # Extract package information from the XML
        $xmlContent.SelectNodes("//atom:entry", $nsManager) | ForEach-Object {
            $isLatestVersion = $_.SelectSingleNode("m:properties/d:IsLatestVersion", $nsManager).InnerText

            # There are multiple versions of packages, but we only display the latest
            if ($isLatestVersion -eq "true") {
                $packageName = $_.SelectSingleNode("m:properties/d:Id", $nsManager).InnerText
                $packageAuthor = $_.SelectSingleNode("atom:author/atom:name", $nsManager).InnerText
                $packageVersion = $_.SelectSingleNode("m:properties/d:Version", $nsManager).InnerText
                $packageSummary = $_.SelectSingleNode("m:properties/d:Description", $nsManager).InnerText

                # Check if package name is not in the blocklist
                if ($packageName -notin $blockList) {
                    $packages += [PSCustomObject]@{
                        PackageName   = $packageName
                        PackageAuthor = $packageAuthor
                        PackageVersion = $packageVersion
                        PackageSummary = $packageSummary
                    }
                }
            }
        }

        # Check if there is a next link in the XML and set the API URL to that link if it exists
        $nextLink = $xmlContent.SelectSingleNode("//atom:link[@rel='next']/@href", $nsManager)
        $apiUrl = $nextLink."#text"
    }
    while ($apiUrl -ne $null)

    return $packages
}

function Get-ChocoPackage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PackageName
    )

    try {
        # Call Chocolatey API to get package metadata
        $response = Invoke-RestMethod -Uri ('https://community.chocolatey.org/api/v2/Packages()?$filter=Id%20eq%20%27' + $PackageName + '%27&$orderby=Version%20desc&$top=1')

        if (!$response) {
            return $false
        }

        return [PSCustomObject]@{
            PackageName = $PackageName
            PackageAuthor = $response.author.name
            PackageVersion = $response.properties.version
            PackageSummary = $response.summary.InnerText
        }
    }
    catch {
        return $false
    }
}


################################# Functions that Set GUI Controls #################################

function Set-SelectedPackages {
    
    # Get the packages for the specified profile
    $packagesFromProfile = Get-PackagesFromProfile -ProfileName $global:selectedProfile

    if (-not $null -eq $packagesFromProfile) {
        # Update the SelectedPackagesList with the packages from the profile
        $SelectedPackagesList.Items.Clear()
        $SelectedPackagesList.Items.AddRange($packagesFromProfile.name)

        # Update the count labels
        $SelectedCountLabel.text = "Total: $($SelectedPackagesList.Items.count)"
    }
}

function Set-AvailablePackages {
    
    # Update the AvailablePackagesList with all the package names from the $global:packageData that are not in the $SelectedPackagesList.Items
    $AvailablePackagesList.Items.Clear()

    $filteredPackages = $global:packageData.PackageName | Where-Object { $_ -notin $SelectedPackagesList.Items }
    
    # Add items only if there are items to add
    if ($filteredPackages.Count -gt 0) {
        $AvailablePackagesList.Items.AddRange($filteredPackages)
    }

    # Update the count labels
    $AvailableCountLabel.text = "Total: $($AvailablePackagesList.Items.count)"
}



function Set-PackageInformation {
    param (
        [string]$PackageName
    )

    if ($PackageName -notmatch "\.vm$") {
        $package = Get-ChocoPackage -PackageName $PackageName
    } else {
        # Get the available package list
        $package = $global:packageData | Where-Object { $_.PackageName -eq $PackageName }
    }

    # Populate the package information fields
    if ($package) {
        $Description.Text = $package.PackageSummary
        $Authors.Text     = $package.PackageAuthor
        $Version.Text     = $package.PackageVersion
    } else {
        Write-Host "[!] Package not found."
    }
}


function Set-ProfilePreset {
    param (
        [string]$ProfileName
    )

    # Change the selected profile
    $global:selectedProfile = $ProfileName

    # Re-render the package lists
    Set-SelectedPackages
    Set-AvailablePackages

    # Check if SelectedPackagesList is empty
    if ($SelectedPackagesList.Items.Count -gt 0) {
        # If not empty, set the package info to the first package in the selected list
        Set-PackageInformation -PackageName $SelectedPackagesList.Items[0]
    }
    else {
        # If empty, set the package info to the first package in the available list
        Set-PackageInformation -PackageName $AvailablePackagesList.Items[0]
    }
}

################################# Functions that Select Packages #################################

function Add-SelectedPackage {

    $selectedItem = $AvailablePackagesList.SelectedItem

    # Move the selected package over to selected listbox from available
    if ($selectedItem) {
        $SelectedPackagesList.Items.Add($selectedItem)
        $AvailablePackagesList.Items.Remove($selectedItem)

        # Update the total counts
        $SelectedCountLabel.Text = "Total: $($SelectedPackagesList.Items.Count)"
        $AvailableCountLabel.Text = "Total: $($AvailablePackagesList.Items.Count)"
    }
}

function Add-AllPackages {
    # Move all items from $AvailablePackagesList.Items to $SelectedPackagesList.Items
    foreach ($item in $AvailablePackagesList.Items) {
        $SelectedPackagesList.Items.Add($item)
    }

    # Empty out the $AvailablePackagesList.Items
    $AvailablePackagesList.Items.Clear()

    # Update the count labels
    $SelectedCountLabel.text = "Total: $($SelectedPackagesList.Items.Count)"
    $AvailableCountLabel.text = "Total: $($AvailablePackagesList.Items.Count)"
}

function Remove-SelectedPackage {
    $selectedItem = $SelectedPackagesList.SelectedItem

    # Move over the selected package from selected list to available
    if ($selectedItem) {
        $AvailablePackagesList.Items.Add($selectedItem)
        $SelectedPackagesList.Items.Remove($selectedItem)

        # Update the total counts
        $SelectedCountLabel.Text = "Total: $($SelectedPackagesList.Items.Count)"
        $AvailableCountLabel.Text = "Total: $($AvailablePackagesList.Items.Count)"
    }
}

function Remove-AllPackages {

    # Add each item from selected to available
    foreach ($item in $SelectedPackagesList.Items) {
        $AvailablePackagesList.Items.Add($item)
    }

    # Clear out the selected listbox
    $SelectedPackagesList.Items.Clear()

    $SelectedCountLabel.Text = "Total: $($SelectedPackagesList.Items.Count)"
    $AvailableCountLabel.Text = "Total: $($AvailablePackagesList.Items.Count)"
}

################################# Functions that Save Profiles #################################

function Save-Profile {
    param (
        [string]$ProfilePath = $(Join-Path -Path $PSScriptRoot (".\Profiles" + "\Custom.xml"))
    )

    # Get the path to the XML of the preset we're basing the profile on and read it into memory
    $selectedProfilePath = ($global:profileData | Where-Object { $_.ProfileName -eq $global:selectedProfile }).XmlPath
    [xml]$xmlContent = Get-Content -Path $selectedProfilePath

    # Remove the profile if one already exists with the same name
    if (Test-Path -Path $ProfilePath) {
        Remove-Item -Path $ProfilePath -Force
    }

    # Clear out the packages section of the preset
    $packagesNode = $xmlContent.config.packages
    $packagesNode.RemoveAll()

    # Overwrite the packages section with our own from the selected packages listbox
    foreach ($item in $SelectedPackagesList.Items) {
        $packageNode = $xmlContent.CreateElement("package")
        $packageNode.SetAttribute("name", $item)
        $packagesNode.AppendChild($packageNode)
    }

    $xmlContent.Save($ProfilePath)
    $global:profileData = Get-ProfileData
}

function Save-ProfileAs {

    $Title = "Save CommandoVM Profile As"
    $Filter = "XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    $InitialDirectory = Join-Path $PSScriptRoot ".\Profiles"

    # Create a save-as dialog window at the profiles directory
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Title = $Title
    $saveFileDialog.Filter = $Filter
    $saveFileDialog.InitialDirectory = $InitialDirectory

    $result = $saveFileDialog.ShowDialog()

    # If the user picks a file location, we will pass it to Save-Profile
    if ($result -eq "OK") {
        Save-Profile -ProfilePath $saveFileDialog.FileName
    }
}

################################# Functions that Install Packages #################################

function Install-Profile {
    param (
        [Parameter(Mandatory = $false)]
        [string]$ProfileName,

        [Parameter(Mandatory = $false)]
        [string]$ProfilePath
    )

    if (-not $ProfileName -and -not $ProfilePath) {
        throw "Either ProfileName or ProfilePath must be specified."
    }

    try {
        if (Check-ChocoBoxstarterVersions) {
            Check-BoxstarterConfig
            Check-ChocoConfig
        } else {
            Check-ChocoBoxstarterInstalls
            Check-BoxstarterConfig
            Check-ChocoConfig
        }
        Check-PowerOptions
        Commando-Configure -configFile $debloatConfig
        Commando-Configure -configFile $userConfig

        Import-Module "${Env:ProgramData}\boxstarter\boxstarter.chocolatey\boxstarter.chocolatey.psd1" -Force

        Write-Host "Installing the common.vm shared module" -ForegroundColor Yellow
        choco install common.vm -y --force
        refreshenv

        $PackageName = "flarevm.installer.vm"

        if (-not $ProfilePath) {
            $ProfilePath = Join-Path $PSScriptRoot ("\Profiles\" + $ProfileName + ".xml")
        }
        
        $destinationPath = Join-Path ${Env:VM_COMMON_DIR} "config.xml"

        if (Test-Path $ProfilePath) {
            Copy-Item $ProfilePath $destinationPath -Force
            Write-Host "[+] Profile copied to desktop: $ProfileName" -ForegroundColor Green
        } else {
            Write-Host "[!] Error: Profile not found: $ProfileName" -ForegroundColor Red
        }

        $backgroundImage = "${Env:VM_COMMON_DIR}\background.png"
        $sourceImage = Join-Path $PSScriptRoot "Images\background.png"

        if (-not (Test-Path $backgroundImage)) {
            Copy-Item -Path $sourceImage -Destination $backgroundImage
        }

        Write-Host "Installing profile: $ProfileName" -ForegroundColor Yellow
        if ($noPassword.IsPresent -or ($global:credentials -eq "")) {
            $Boxstarter.NoPassword = $true
            Install-BoxstarterPackage -PackageName $PackageName
        } else {
            $Boxstarter.NoPassword = $false
            Install-BoxstarterPackage -PackageName $PackageName -Credential $global:credentials
        }
    }
    catch {
        Write-Host "[!] Error: Failed to install profile: $PackageName" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

################################# Functions that Open GUI Windows #################################

function Open-CheckManager {

    if ($CommandoChecksManager.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        exit
    }
}

function Open-Installer {

    # Populate the profile selector combo box
    $ProfileSelector.Items.Clear()
    $ProfileSelector.Items.AddRange($global:profileData.ProfileName)

    # Set the value of the profile selector to default
    $ProfileSelector.Text = $global:selectedProfile

    [void]$CommandoInstaller.ShowDialog()
}

function Open-ProfileManager {

    # Populate the combo box with profile names from the $global:profileData array
    $PresetSelector.Items.Clear()
    $PresetSelector.Items.AddRange($global:profileData.ProfileName)

    # Set the value of $PresetSelector.Text to $global:selectedProfile
    $PresetSelector.Text = $global:selectedProfile

    # Render the package lists
    Set-SelectedPackages
    Set-AvailablePackages

    # Check if SelectedPackagesList is empty
    if ($SelectedPackagesList.Items.Count -gt 0) {
        # If not empty, set the package info to the first package in the selected list
        Set-PackageInformation -PackageName $SelectedPackagesList.Items[0]
    }
    else {
        # If empty, set the package info to the first package in the available list
        Set-PackageInformation -PackageName $AvailablePackagesList.Items[0]
    }

    [void]$CommandoProfileManager.ShowDialog()
}


function Open-AddChocoPackage {

    $ChocoPackageTextBox.Text = ""
    $ChocoPackageErrorLabel.Visible = $false
    $ChocoAddPackageButton.Enabled = $false

    if ($CommandoChocoManager.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $SelectedPackagesList.Items.Add($ChocoPackageTextBox.Text)
        $SelectedCountLabel.Text = "Total: " + $SelectedPackagesList.Items.Count
    }
}

function Open-PasswordEntry {
    $PasswordInfoLabel.Visible = $true
    $PasswordTextBox.Text = ""
    
    if ($CommandoPasswordManager.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $Password = $PasswordTextBox.Text
        if ($Password -ne "") {
            $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $global:credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $env:username, $SecurePassword
        }
        [void]$CommandoInstaller.Close()
        return $true
    } else {
        return $false
    }
}

#################################################################################################
#################################################################################################
###################################### Installer Workflows ######################################
#################################################################################################
#################################################################################################

# QuickEdit and Insert modes can sometimes freeze the powershell.exe window
Set-ItemProperty -Path 'HKCU:\Console' -Name 'QuickEdit' -Value 0
Set-ItemProperty -Path 'HKCU:\Console' -Name 'InsertMode' -Value 0

# Load debloating and configuration modules
Import-Module (Join-Path $PSScriptRoot "Modules\configureVM.psm1") -Force
$debloatConfig = Join-Path $PSScriptRoot "Modules\debloatConfig.xml"
$userConfig = Join-Path $PSScriptRoot "Modules\userConfig.xml"

# Setting global variables
$global:checksPassed = $true
$global:selectedProfile = "Default"
$global:credentials = ""

################################# GUI Workflow #################################

if (-not $cli.IsPresent) {

    if (-not $skipChecks.IsPresent) {

        # Make sure that the user completed all pre-install steps
        if (Check-Admin) {
            $RunningAsAdmin.Text = "True"
            $RunningAsAdmin.ForeColor = $successColor
        } else {
            $global:checksPassed = $false
        }

        if (Check-ExecutionPolicy) {
            $ExecutionPolicy.Text = "True"
            $ExecutionPolicy.ForeColor = $successColor
        } else {
            $global:checksPassed = $false
        }

        if (-not $victim.IsPresent) {
            if (Check-DefenderAndTamperProtection) {
                $WindowsDefender.Text = "True"
                $WindowsDefender.ForeColor = $successColor
            }
        } else {
            $WindowsDefender.Text = "Skip"
            $WindowsDefender.ForeColor = $skippedColor
            $global:selectedProfile = "Victim"
        }
        if (-not $victim.IsPresent) {
            if (Check-DefenderAndTamperProtection) {
                $WindowsDefender.Text = "True"
                $WindowsDefender.ForeColor = $successColor
            }
        } else {
            $WindowsDefender.Text = "Skip"
            $WindowsDefender.ForeColor = $skippedColor
            $global:selectedProfile = "Victim"
        }

        if (Check-SupportedOS) {
            $WindowsRelease.Text = "True"
            $WindowsRelease.ForeColor = $successColor
        } else {
            $global:checksPassed = $false
        }

        if (Check-VM) {
            $RunningVM.Text = "True"
            $RunningVM.ForeColor = $successColor
        } else {
            $global:checksPassed = $false
        }

        if (Check-Storage) {
            $EnoughHardStorage.Text = "True"
            $EnoughHardStorage.ForeColor = $successColor
        } else {
            $global:checksPassed = $false
        }

        if ($global:checksPassed) {
            $ChecksCompleteButton.enabled = $true
        }

        Open-CheckManager
    }
    
    if ($global:checksPassed -or $skipChecks.IsPresent) {

        # Fetch profiles and packages
        Write-Host "[i] Retrieving available packages. Please wait." -ForegroundColor Blue
        $global:profileData = Get-ProfileData
        $global:packageData = Get-AvailablePackages

        Open-Installer
    }
}

################################# CLI Workflow #################################

if ($cli.IsPresent) {

    Write-Host "`n$asciiArt" -ForegroundColor Red
    Write-Host "`t`tComplete Mandiant Offensive VM - Version 3.0" -ForegroundColor Red
    Write-Host "`t`t`tcommandovm@mandiant.com" -ForegroundColor DarkYellow

    if ($customProfile -eq "") {
        Write-Host "[i] No profile specified, selecting default" -ForegroundColor Blue
        $customProfile = Join-Path $PSScriptRoot "Profiles/Default.xml"
    }

    if (-not $noPassword.IsPresent) {
        # Get user credentials for autologin during reboots
        if ([string]::IsNullOrEmpty($password)) {
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds" -Name "ConsolePrompting" -Value $True
            Start-Sleep -Milliseconds 500
            Write-Host "[i] No password provided. Enter it now or use -noPassword if blank." -ForegroundColor Blue
            $global:credentials = Get-Credential ${Env:username}
        } else {
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            $global:credentials = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList ${Env:username}, $securePassword
        }
    }

    if (-not $skipChecks.IsPresent) {
        # Make sure that the user completed all pre-install steps
        Write-Host "=================== CommandoVM Pre-Installation Checks ==================="

        if (Check-Admin) {
            Write-Host "`t[+] Running as administrator" -ForegroundColor Green
        } else {
            $global:checksPassed = $false
            Write-Host "`t[-] Not running as administrator" -ForegroundColor Red
        }

        if (Check-ExecutionPolicy) {
            Write-Host "`t[+] Execution policy is unrestricted" -ForegroundColor Green
        } else {
            $global:checksPassed = $false
            Write-Host "`t[-] Execution policy is not unrestricted" -ForegroundColor Red
        }
        
        if (-not $victim.IsPresent) {
            if (Check-DefenderAndTamperProtection) {
                Write-Host "`t[+] Windows Defender and Tamper Protection are disabled" -ForegroundColor Green
            } else {
                $global:checksPassed = $false
                Write-Host "`t[-] Windows Defender and Tamper Protection are enabled" -ForegroundColor Red
            }
        } else {
            Write-Host "`t[i] Skipping Windows Defender checks" -ForegroundColor Blue
        }
        if (-not $victim.IsPresent) {
            if (Check-DefenderAndTamperProtection) {
                Write-Host "`t[+] Windows Defender and Tamper Protection are disabled" -ForegroundColor Green
            } else {
                $global:checksPassed = $false
                Write-Host "`t[-] Windows Defender and Tamper Protection are enabled" -ForegroundColor Red
            }
        } else {
            Write-Host "`t[i] Skipping Windows Defender checks" -ForegroundColor Blue
        }

        if (Check-SupportedOS) {
            Write-Host "`t[+] Current Windows release is supported by CommandoVM" -ForegroundColor Green
        } else {
            $global:checksPassed = $false
            Write-Host "`t[-] Current Windows release is not supported by CommandoVM" -ForegroundColor Red
        }

        if (Check-VM) {
            Write-Host "`t[+] Virtual Machine detected" -ForegroundColor Green
        } else {
            $global:checksPassed = $false
            Write-Host "`t[-] Virtual Machine not detected" -ForegroundColor Red
        }

        if (Check-Storage) {
            Write-Host "`t[+] At least 70GB of storage detected" -ForegroundColor Green
        } else {
            $global:checksPassed = $false
            Write-Host "`t[-] At least 70GB of storage not found" -ForegroundColor Red
        }
    }

    if ($global:checksPassed -or $skipChecks.IsPresent) {
        Write-Host "===================== Installing CommandoVM ====================="
        Install-Profile -ProfileName $customProfile
    } else {
        Write-Host "`n[i] Some checks failed. Use the -skipChecks flag if you know what you are doing" -ForegroundColor Blue
    }
}
