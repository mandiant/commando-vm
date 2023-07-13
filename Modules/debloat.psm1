# COMMANDO-VM DEBLOATER

function Commando-Remove-App {
# Function for removing Apps
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$appName
    )

    try {
        # Check if the app is installed
        $installedPackage = Get-AppxPackage -Name $appName -ErrorAction SilentlyContinue
        
        if ($installedPackage) {
            $packageFullName = $installedPackage.PackageFullName
            $result = Remove-AppxPackage -Package $packageFullName -ErrorAction Stop

            if ($null -eq $result) {
                Write-Output "[DEBLOAT] Installed $appName has been successfully removed."
            } else {
                Write-Output "[DEBLOAT] Failed to remove installed app $appName."
            }
        }
        else {
            Write-Output "[DEBLOAT] Installed $appName not found on the system."
        }
        # Check if the app is provisioned
        $provisionedPackage = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName } -ErrorAction SilentlyContinue
        if ($provisionedPackage) {
            $result = Remove-AppxProvisionedPackage -PackageName $provisionedPackage.PackageName -Online -ErrorAction Stop

            if ($result) {
                Write-Output "[DEBLOAT] Provisioned $appName has been successfully removed."
            } else {
                Write-Output "[DEBLOAT] Failed to remove porvisioned app $appName."
            }
        } else {
            Write-Output "[DEBLOAT] Provisioned $appName not found on the system."
        }
    } 
    catch {
        Write-Error "An error occurred while removing the app or provisioned package. Error: $_"
    }
}


function Commando-Remove-Service {
# Function for removing Services
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$serviceName
    )

    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop

        if ($service) {
            $service | Set-Service -StartupType Manual -ErrorAction Stop
            Write-Output "[DEBLOAT] Service $serviceName has been disabled."
        } else {
            Write-Output "[DEBLOAT] Service $serviceName not found."
        }
    }
    catch {
        Write-Error "[DEBLOAT] An error occurred while setting the service startup type. Error: $_"
    }
}

function Commando-Remove-RegistryValue {
    # Function for setting Registry items
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $path,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $value,

        [Parameter(Mandatory=$true)]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "QWord", "MultiString", "Unknown")]
        [string] $type,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $data
    )

    try {
        # Validate the value based on the type parameter
        if ($type -eq "DWord" -or $type -eq "QWord") {
            $validatedData = [int64]::Parse($data)
        }
        elseif ($type -eq "Binary") {
            $validatedData = [byte[]]($data -split " " | % { [convert]::ToByte($_, 16) })
        }
        else {
            $validatedData = $data
        }

        # check if path exists. If not, create the path for the registry value
        if (!(Test-Path -Path $path)) {
            # Create the registry key
            New-Item -Path $path -Force | Out-Null
            Write-Output "Registry key created: $path"
        }
        else {
            Write-Output "Registry key already exists: $path"
        }

        Set-ItemProperty -Path $path -Name $value -Value $validatedData -Type $type -Force | Out-Null
        Write-Output "[DEBLOAT] $name has been successfully updated."
    }
    catch {
        Write-Error "Failed to update the registry value. Error: $_"
    }
}

function Commando-Remove-Path {
# Function for removing Paths/Programs
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$name,

        [Parameter(Mandatory=$true)]
        [ValidateSet("file", "dir")]
        [string]$type,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$path
    )

    try {
        if ($type -eq "file") {
            if (Test-Path -Path $path -PathType Leaf) {
                Remove-Item -Path $path -Force
                Write-Output "[DEBLOAT] $name has been successfully removed."
            } else {
                Write-Output "[DEBLOAT] $path does not exist."
            }
        }
        elseif ($type -eq "dir") {
            if (Test-Path -Path $path -PathType Container) {
                Remove-Item -Path $path -Recurse -Force
                Write-Output "[DEBLOAT] $name has been successfully removed."
            } else {
                Write-Output "[DEBLOAT] $path does not exist."
            }
        }
    }
    catch {
        Write-Error "An error occurred while removing the $type $path. Error: $_"
    }
}


function Commando-Remove-Custom{
# Function for removing items in need of custom code.
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$cmds
    )

    try {
        Write-Output "[DEBLOAT] Executing commands for '$name':"
        foreach ($cmd in $cmds) {
            Write-Output "`tExecuting command: $cmd"
            start-process powershell -ArgumentList "-WindowStyle","Hidden","-Command",$cmd -Wait
            Write-Host "Process completed. Moving to next."
        }
        Write-Output "[DEBLOAT] All commands for '$name' have been executed successfully."
    }
    catch {
        Write-Error "An error occurred while executing commands for '$name'. Error: $_"
    }
}


# DEBLOATER MAIN
function Commando-Debloat {
    param(
        [Parameter(Position = 0)]
        [string]$debloatConfig = "./debloatConfig.xml"
    )

    try {
        # Load and parse the XML config file
        $config = [xml](Get-Content $debloatConfig)

        # Process the apps
        $config.config.apps.app | ForEach-Object {
            $appName = $_.name
            Commando-Remove-App -appName $appName
        }

        # Process the services
        $config.config.services.service | ForEach-Object {
            $serviceName = $_.name
            Commando-Remove-Service -serviceName $serviceName
        }

        # Process the registry items
        $config.config."registry-items"."registry-item" | ForEach-Object {
            $name = $_.name
            $path = $_.path
            $value = $_.value
            $type = $_.type
            $data = $_.data
            Commando-Remove-RegistryValue -name $name -path $path -value $value -type $type -data $data
        }

        # Process the path items
        $config.config."path-items"."path-item" | ForEach-Object {
            $name = $_.name
            $type = $_.type
            $path = $_.path
            Commando-Remove-Path -name $name -type $type -path $path
        }

        # Process the custom items
        $config.config."custom-items"."custom-item" | ForEach-Object {
            $name = $_.name
            $cmds = @($_.cmd | ForEach-Object { $_.value })
            Commando-Remove-Custom -name $name -cmds $cmds
        }

        # Unpinning all Start Tiles
        Write-Output "[DEBLOAT] Unpinning all Start Menu Tiles."
        $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "An error occurred while applying debloat. Error: $_"
    }
}

# Export Function
Export-ModuleMember -Function Commando-Debloat