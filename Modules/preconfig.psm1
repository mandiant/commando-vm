# COMMANDO VM PRECONFIG

# THE PLAN IS TO MOVE THIS CODE OUT TO A PACKAGE WITH A CONFIG

function Commando-Prompt {
    $psprompt = @"
    function prompt {
        Write-Host ("COMMANDO " + `$(get-date)) -ForegroundColor Red
        Write-Host ("PS " + `$(Get-Location) + " >") -NoNewLine -ForegroundColor White
        return " "
    }
"@

    # Ensure profile file exists and append new content to it, not overwriting old content
    if (!(Test-Path $profile)) {
        New-Item -ItemType File -Path $profile -Force | Out-Null
    }
    Add-Content -Path $profile -Value $psprompt

    # Add timestamp to cmd prompt
    Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("Y21kIC9jICdzZXR4IFBST01QVCBDT01NQU5ETyRTJGQkcyR0JF8kcCQrJGcn"))) | Out-Null

    Write-Host "[+] Timestamps added to cmd prompt and PowerShell" -ForegroundColor Green
}

function Commando-Logging {
    if ($PSVersionTable -And $PSVersionTable.PSVersion.Major -ge 5) {
        Write-Host "[+] Enabling PowerShell Script Block Logging" -ForegroundColor Green
        $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell'
        if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
        }
        $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'
        if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
        }
        New-ItemProperty -Path $psLoggingPath -Name "EnableInvocationHeader" -Value 1 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $psLoggingPath -Name "EnableTranscripting" -Value 1 -PropertyType DWORD -Force | Out-Null
        New-ItemProperty -Path $psLoggingPath -Name "OutputDirectory" -Value (Join-Path ${Env:UserProfile} "Desktop\PS_Transcripts") -PropertyType String -Force | Out-Null
        
        $psLoggingPath = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-Not (Test-Path $psLoggingPath)) {
          New-Item -Path $psLoggingPath -Force | Out-Null
        }
        New-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWORD -Force | Out-Null
        Write-Host "`t[i] Powershell transcripts will be saved to the desktop." -ForegroundColor Green
      }
}

function Commando-Darkmode {
    Write-Output "[+] Setting Dark Mode for System..." -ForegroundColor Green
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

function Commando-Hostname {
    Write-Host "[+] Renaming host to 'commando'" -ForegroundColor Green
    Rename-Computer -NewName "commando"
}

# PRECONFIG MAIN
function Commando-Configure {
    Commando-Logging
    Commando-Prompt
    Commando-Darkmode
    Commando-Hostname
}

# Export Function
Export-ModuleMember -Function Commando-Configure