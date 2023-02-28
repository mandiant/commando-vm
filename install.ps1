<#
    .SYNOPSIS
        Installation script for CommandoVM.
    .DESCRIPTION
        Placeholder
    .PARAMETER password
        Current user password to allow reboot resiliency via Boxstarter
    .PARAMETER noPassword
        Switch parameter indicating a password is not needed for reboots.
    .PARAMETER customConfig
        Path to a configuration XML file. May be a file path or URL.
    .PARAMETER noWait
        Switch parameter to skip installation message before installation begins.
    .PARAMETER noGui
        Switch parameter to skip customization GUI.
    .PARAMETER noReboots
        Switch parameter to prevent reboots.
    .PARAMETER noChecks
        Switch parameter to skip validation checks (not recommended).
    .EXAMPLE
        .\install.ps1
    .LINK
        https://github.com/mandiant/commando-vm
        https://github.com/mandiant/VM-Packages
#>
param (
  [string]$password = $null,
  [switch]$noPassword,
  [string]$customConfig = $null,
  [switch]$noWait,
  [switch]$noGui,
  [switch]$noReboots,
  [switch]$noChecks
)

if (-not $noGui.IsPresent) {

  Write-Host "[+] Starting CommandoVM Installer GUI ..."

  #########################################################################
  ######################## GUI INSTALLER FUNCTIONS ########################
  #########################################################################

  function Get-AvailableProfiles {
    $profiles = @()
    $availableProfilesPath = Join-Path $PSScriptRoot "Profiles\"

    Get-ChildItem -Path $availableProfilesPath -Filter *.xml | ForEach-Object {
        $profileName = $_.BaseName
        $profiles += $profileName
    }

    return $profiles
  }

  function Set-AvailableProfiles {
    $profiles = Get-AvailableProfiles

    $ProfileSelector.Items.Clear()
    $ProfileSelector.Items.AddRange($profiles)

    $PresetSelector.Items.Clear()
    $PresetSelector.Items.AddRange($profiles)

    $defaultIndex = $ProfileSelector.Items.IndexOf("Default")
    $ProfileSelector.SelectedIndex = $defaultIndex

    $defaultIndex = $PresetSelector.Items.IndexOf("Default")
    $PresetSelector.SelectedIndex = $defaultIndex
  }

  function Get-DiskSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ProfileName
    )

    $profilePath = Join-Path $PSScriptRoot "Profiles\$ProfileName.xml"

    if (Test-Path $profilePath) {
        $xml = [xml](Get-Content $profilePath)
        $minDiskSpace = $xml.config.envs.env | Where-Object { $_.name -eq "MIN_DISK_SPACE" } | Select-Object -ExpandProperty value
        return $minDiskSpace
    }
  }

  # TODO: Don't default the Custom profile size to 40GB
  function Set-DiskSpaceLabel {
    $selectedProfile = $ProfileSelector.Text

    if ($selectedProfile  -eq "Custom") {
      $RecommendedDiskSpace.Text = "40 GB+"
    } else {
      $minDiskSpace = Get-DiskSpace -ProfileName $selectedProfile
      $RecommendedDiskSpace.Text = "$minDiskSpace GB+"
    }
  }

  function Open-ProfileManager {
    $presetIndex = $ProfileSelector.SelectedIndex
    $PresetSelector.SelectedIndex = $presetIndex

    $ProfileSelector.Items.Add("Custom")
    $customIndex = $ProfileSelector.Items.IndexOf("Custom")
    $ProfileSelector.SelectedIndex = $customIndex

    $CommandoProfileManager.ShowDialog()
  }

  function Start-Install {
    Write-Host "[-] Not implemented yet ..."
  }

  ###########################################################################
  ######################## MAIN INSTALLER WINDOW GUI ########################
  ###########################################################################

  Add-Type -Name Window -Namespace Console -MemberDefinition '
  [DllImport("Kernel32.dll")]
  public static extern IntPtr GetConsoleWindow();

  [DllImport("user32.dll")]
  public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
  [Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0)

  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Application]::EnableVisualStyles()

  $CommandoInstaller               = New-Object system.Windows.Forms.Form
  $CommandoInstaller.ClientSize    = New-Object System.Drawing.Point(693,574)
  $CommandoInstaller.text          = "CommandoVM Installer"
  $CommandoInstaller.TopMost       = $false
  # TODO, add $CommandoInstaller.Icon

  $CommandoLogo                    = New-Object system.Windows.Forms.PictureBox
  $CommandoLogo.width              = 338
  $CommandoLogo.height             = 246
  $CommandoLogo.location           = New-Object System.Drawing.Point(179,37)
  $CommandoLogo.imageLocation      = "https://raw.githubusercontent.com/mandiant/commando-vm/master/Commando.png"
  $CommandoLogo.SizeMode           = [System.Windows.Forms.PictureBoxSizeMode]::zoom

  $InstallButton                   = New-Object system.Windows.Forms.Button
  $InstallButton.text              = "Install"
  $InstallButton.width             = 104
  $InstallButton.height            = 60
  $InstallButton.location          = New-Object System.Drawing.Point(548,446)
  $InstallButton.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
  $InstallButton.Add_Click({Start-Install})

  $ProfileSelector                 = New-Object system.Windows.Forms.ComboBox
  $ProfileSelector.text            = "Select Profile"
  $ProfileSelector.width           = 141
  $ProfileSelector.height          = 108
  $ProfileSelector.location        = New-Object System.Drawing.Point(380,449)
  $ProfileSelector.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  $ProfileSelector.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList
  $ProfileSelector.Add_SelectedIndexChanged({Set-DiskSpaceLabel})

  $ConfigureProfileButton          = New-Object system.Windows.Forms.Button
  $ConfigureProfileButton.text     = "Configure Profile"
  $ConfigureProfileButton.width    = 142
  $ConfigureProfileButton.height   = 29
  $ConfigureProfileButton.location  = New-Object System.Drawing.Point(380,478)
  $ConfigureProfileButton.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  $ConfigureProfileButton.Add_Click({Open-ProfileManager})

  $RecommendedDiskSpace            = New-Object system.Windows.Forms.Label
  $RecommendedDiskSpace.text       = "40GB+"
  $RecommendedDiskSpace.AutoSize   = $true
  $RecommendedDiskSpace.width      = 25
  $RecommendedDiskSpace.height     = 10
  $RecommendedDiskSpace.location   = New-Object System.Drawing.Point(590,523)
  $RecommendedDiskSpace.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

  # Profile Labels

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

  # Profile Label Descriptions

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
  $ProfileLabelDescriptionDeveloper.text  = "- comes with development tools"
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

  $RecommendedDiskSpaceLabel       = New-Object system.Windows.Forms.Label
  $RecommendedDiskSpaceLabel.text  = "Recommended Disk Space - "
  $RecommendedDiskSpaceLabel.AutoSize  = $true
  $RecommendedDiskSpaceLabel.width  = 25
  $RecommendedDiskSpaceLabel.height  = 10
  $RecommendedDiskSpaceLabel.location  = New-Object System.Drawing.Point(390,523)
  $RecommendedDiskSpaceLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
  $RecommendedDiskSpaceLabel.ForeColor  = [System.Drawing.ColorTranslator]::FromHtml("#c10000")

  # Disclaimer Labels

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

  $CommandoInstaller.controls.AddRange(@($CommandoLogo,$InstallButton,$ProfileSelector,$ConfigureProfileButton,$ProfileLabels,$RecommendedDiskSpaceLabel,$DisclaimerLabelLine1,$DisclaimerLabelLine2,$DisclaimerLabelLine3,$DisclaimerLabelLine4,$RecommendedDiskSpace))
  $ProfileLabels.controls.AddRange(@($ProfileLabelDescriptionLite,$Label1,$ProfileLabelLite,$ProfileLabelFull,$ProfileLabelDescriptionFull,$ProfileLabelDefault,$ProfileLabelDescriptionDefault,$ProfileLabelDeveloper,$ProfileLabelDescriptionDeveloper,$ProfileLabelVictim,$ProfileLabelDescriptionVictim))
  
  ############################################################################
  ######################## PROFILE MANAGER WINDOW GUI ########################
  ############################################################################

  $CommandoProfileManager          = New-Object system.Windows.Forms.Form
  $CommandoProfileManager.ClientSize  = New-Object System.Drawing.Point(660,686)
  $CommandoProfileManager.text     = "CommandoVM Profile Manager"
  $CommandoProfileManager.TopMost  = $false
  # TODO: add $CommandoProfileManager.icon
  
  $PackageInstallationGroup        = New-Object system.Windows.Forms.Groupbox
  $PackageInstallationGroup.height  = 386
  $PackageInstallationGroup.width  = 563
  $PackageInstallationGroup.text   = "Package Installation"
  $PackageInstallationGroup.location  = New-Object System.Drawing.Point(47,37)

  # Package Categories

  $PresetSelector                  = New-Object system.Windows.Forms.ComboBox
  $PresetSelector.text             = "Default"
  $PresetSelector.width            = 122
  $PresetSelector.height           = 20
  $PresetSelector.location         = New-Object System.Drawing.Point(252,11)
  $PresetSelector.Font             = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  $PresetSelector.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList

  $SelectedPackagesCategory        = New-Object system.Windows.Forms.ComboBox
  $SelectedPackagesCategory.width  = 158
  $SelectedPackagesCategory.height  = 22
  $SelectedPackagesCategory.location  = New-Object System.Drawing.Point(94,81)
  $SelectedPackagesCategory.Font   = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  $SelectedPackagesCategory.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList

  $AvailablePackagesCategory       = New-Object system.Windows.Forms.ComboBox
  $AvailablePackagesCategory.width  = 158
  $AvailablePackagesCategory.height  = 22
  $AvailablePackagesCategory.location  = New-Object System.Drawing.Point(389,81)
  $AvailablePackagesCategory.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  $AvailablePackagesCategory.DropDownStyle   = [System.Windows.Forms.ComboBoxStyle]::DropDownList

  # Package Lists

  $SelectedPackagesList            = New-Object system.Windows.Forms.ListView
  $SelectedPackagesList.text       = "listView"
  $SelectedPackagesList.width      = 237
  $SelectedPackagesList.height     = 262
  $SelectedPackagesList.location   = New-Object System.Drawing.Point(15,112)
  
  $AvailablePackagesList           = New-Object system.Windows.Forms.ListView
  $AvailablePackagesList.text      = "listView"
  $AvailablePackagesList.width     = 237
  $AvailablePackagesList.height    = 262
  $AvailablePackagesList.location  = New-Object System.Drawing.Point(310,112)
  
  # Profile Manager Buttons

  $DoneButton                      = New-Object system.Windows.Forms.Button
  $DoneButton.text                 = "Done"
  $DoneButton.width                = 94
  $DoneButton.height               = 30
  $DoneButton.location             = New-Object System.Drawing.Point(433,639)
  $DoneButton.Font                 = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $SaveProfileButton               = New-Object system.Windows.Forms.Button
  $SaveProfileButton.text          = "Save Profile"
  $SaveProfileButton.width         = 124
  $SaveProfileButton.height        = 30
  $SaveProfileButton.location      = New-Object System.Drawing.Point(284,639)
  $SaveProfileButton.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $ResetProfileButton              = New-Object system.Windows.Forms.Button
  $ResetProfileButton.text         = "Reset Profile"
  $ResetProfileButton.width        = 127
  $ResetProfileButton.height       = 30
  $ResetProfileButton.location     = New-Object System.Drawing.Point(132,639)
  $ResetProfileButton.Font         = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  # Package Selection Buttons

  $AddPackageButton                = New-Object system.Windows.Forms.Button
  $AddPackageButton.text           = "<"
  $AddPackageButton.width          = 43
  $AddPackageButton.height         = 30
  $AddPackageButton.location       = New-Object System.Drawing.Point(259,151)
  $AddPackageButton.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $AddAllPackagesButton            = New-Object system.Windows.Forms.Button
  $AddAllPackagesButton.text       = "<<"
  $AddAllPackagesButton.width      = 43
  $AddAllPackagesButton.height     = 30
  $AddAllPackagesButton.location   = New-Object System.Drawing.Point(259,195)
  $AddAllPackagesButton.Font       = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $RemovePackageButton             = New-Object system.Windows.Forms.Button
  $RemovePackageButton.text        = ">"
  $RemovePackageButton.width       = 43
  $RemovePackageButton.height      = 30
  $RemovePackageButton.location    = New-Object System.Drawing.Point(259,262)
  $RemovePackageButton.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $RemoveAllPackagesButton         = New-Object system.Windows.Forms.Button
  $RemoveAllPackagesButton.text    = ">>"
  $RemoveAllPackagesButton.width   = 43
  $RemoveAllPackagesButton.height  = 30
  $RemoveAllPackagesButton.location  = New-Object System.Drawing.Point(259,307)
  $RemoveAllPackagesButton.Font    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  # Package Information
  
  $Authors                         = New-Object system.Windows.Forms.Label
  $Authors.text                    = "Authors"
  $Authors.AutoSize                = $true
  $Authors.width                   = 25
  $Authors.height                  = 10
  $Authors.location                = New-Object System.Drawing.Point(81,29)
  $Authors.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $Version                         = New-Object system.Windows.Forms.Label
  $Version.text                    = "Version"
  $Version.AutoSize                = $true
  $Version.width                   = 25
  $Version.height                  = 10
  $Version.location                = New-Object System.Drawing.Point(81,59)
  $Version.Font                    = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  $Description                     = New-Object system.Windows.Forms.Label
  $Description.text                = "Tool Description"
  $Description.AutoSize            = $false
  $Description.width               = 529
  $Description.height              = 43
  $Description.location            = New-Object System.Drawing.Point(17,115)
  $Description.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  # Package Selection Labels

  $SelectedPackagesLabel           = New-Object system.Windows.Forms.Label
  $SelectedPackagesLabel.text      = "Selected Packages"
  $SelectedPackagesLabel.AutoSize  = $true
  $SelectedPackagesLabel.width     = 25
  $SelectedPackagesLabel.height    = 10
  $SelectedPackagesLabel.location  = New-Object System.Drawing.Point(64,49)
  $SelectedPackagesLabel.Font      = New-Object System.Drawing.Font('Microsoft Sans Serif',12)
  
  $SelectedPackagesCategoryLabel   = New-Object system.Windows.Forms.Label
  $SelectedPackagesCategoryLabel.text  = "Category"
  $SelectedPackagesCategoryLabel.AutoSize  = $true
  $SelectedPackagesCategoryLabel.width  = 25
  $SelectedPackagesCategoryLabel.height  = 10
  $SelectedPackagesCategoryLabel.location  = New-Object System.Drawing.Point(20,83)
  $SelectedPackagesCategoryLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
  
  $AvailablePackagesLabel          = New-Object system.Windows.Forms.Label
  $AvailablePackagesLabel.text     = "Available Packages"
  $AvailablePackagesLabel.AutoSize  = $true
  $AvailablePackagesLabel.width    = 25
  $AvailablePackagesLabel.height   = 10
  $AvailablePackagesLabel.location  = New-Object System.Drawing.Point(360,49)
  $AvailablePackagesLabel.Font     = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

  $AvailablePackagesCategoryLabel   = New-Object system.Windows.Forms.Label
  $AvailablePackagesCategoryLabel.text  = "Category"
  $AvailablePackagesCategoryLabel.AutoSize  = $true
  $AvailablePackagesCategoryLabel.width  = 25
  $AvailablePackagesCategoryLabel.height  = 10
  $AvailablePackagesCategoryLabel.location  = New-Object System.Drawing.Point(315,83)
  $AvailablePackagesCategoryLabel.Font  = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  $PresetSelectorLabel             = New-Object system.Windows.Forms.Label
  $PresetSelectorLabel.text        = "Preset"
  $PresetSelectorLabel.AutoSize    = $true
  $PresetSelectorLabel.width       = 25
  $PresetSelectorLabel.height      = 10
  $PresetSelectorLabel.location    = New-Object System.Drawing.Point(203,14)
  $PresetSelectorLabel.Font        = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

  # Package Information Labels

  $PackageInformationGroup         = New-Object system.Windows.Forms.Groupbox
  $PackageInformationGroup.height  = 173
  $PackageInformationGroup.width   = 562
  $PackageInformationGroup.text    = "Package Information"
  $PackageInformationGroup.location  = New-Object System.Drawing.Point(47,445)
  
  $AuthorsLabel                    = New-Object system.Windows.Forms.Label
  $AuthorsLabel.text               = "Authors:"
  $AuthorsLabel.AutoSize           = $true
  $AuthorsLabel.width              = 25
  $AuthorsLabel.height             = 10
  $AuthorsLabel.location           = New-Object System.Drawing.Point(16,29)
  $AuthorsLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

  $VersionLabel                    = New-Object system.Windows.Forms.Label
  $VersionLabel.text               = "Version:"
  $VersionLabel.AutoSize           = $true
  $VersionLabel.width              = 25
  $VersionLabel.height             = 10
  $VersionLabel.location           = New-Object System.Drawing.Point(17,59)
  $VersionLabel.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))

  $DescriptionLabel                = New-Object system.Windows.Forms.Label
  $DescriptionLabel.text           = "Tool Description"
  $DescriptionLabel.AutoSize       = $true
  $DescriptionLabel.width          = 25
  $DescriptionLabel.height         = 10
  $DescriptionLabel.location       = New-Object System.Drawing.Point(17,89)
  $DescriptionLabel.Font           = New-Object System.Drawing.Font('Microsoft Sans Serif',10,[System.Drawing.FontStyle]([System.Drawing.FontStyle]::Bold))
  
  $CommandoProfileManager.controls.AddRange(@($PackageInstallationGroup,$DoneButton,$SaveProfileButton,$ResetProfileButton,$PackageInformationGroup))
  $PackageInstallationGroup.controls.AddRange(@($SelectedPackagesList,$AvailablePackagesList,$SelectedPackagesLabel,$PresetSelectorLabel,$AddPackageButton,$AddAllPackagesButton,$RemovePackageButton,$RemoveAllPackagesButton,$SelectedPackagesCategory,$SelectedPackagesCategoryLabel,$AvailablePackagesCategoryLabel,$AvailablePackagesCategory,$PresetSelector,$AvailablePackagesLabel))
  $PackageInformationGroup.controls.AddRange(@($AuthorsLabel,$Description,$DescriptionLabel,$VersionLabel,$Authors,$Version))

  #############################################################################
  ######################## VARIABLE MANAGER WINDOW GUI ########################
  #############################################################################

  # Placeholder

  #############################################################################
  ################################ RENDER GUI #################################
  #############################################################################

  Set-AvailableProfiles
  [void]$CommandoInstaller.ShowDialog()

} else {
  Write-Host "[-] CLI Install is not yet implemented..."
}


