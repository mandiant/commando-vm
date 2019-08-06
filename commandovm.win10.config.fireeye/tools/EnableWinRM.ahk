#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn  ; Enable warnings to assist with detecting common errors.
#WinActivateForce


SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.
SetKeyDelay, 50

psScript =
(
    winrm quickconfig -q
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
	Set-Service -Name WinRM -StartupType Automatic
	Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any
    Set-Item wsman:localhost\client\trustedhosts -Value "*" -Force
    Enable-WSManCredSSP -Role "Client" -DelegateComputer "*" -Force
)

RunWait PowerShell.exe -Command &{%psScript%}

title = Local Group Policy Editor
Run, C:\Windows\System32\gpedit.msc
WinWait, %title%, , 5000
IfWinExist %title%
{
	WinActivate %title%
	WinMaximize, %title%
	Sleep, 500
	BlockInput On
	SendInput, {down}{down}{down}{down}{right}					; Expand "Administrative Template"	
	Sleep, 500
	SendInput, {down}{down}{down}{down}{down}{down}{right}		; Expand "System"
	Sleep, 500
	SendInput, c												; Delegate credentials
	Sleep, 500
	SendInput, {tab}											; Switch Pane
	Sleep, 500
	SendInput, {down}{down}{down}{down}							; Delegate fresh creds with NTML-Only server Auth
	Sleep, 500
	SendInput, {enter}
	Sleep, 500
	SendInput, !E
	Sleep, 500
	SendInput, {tab}{tab}{tab}									; Show
	Sleep, 500
	SendInput, {enter}
	Sleep, 500
	SendInput, {tab}{tab}
	Sleep, 500
	SendInput, WSMAN/*
	Sleep, 500
	SendInput, !O       										; OK
	Sleep, 500
	SendInput, {tab}{enter}										; Done
	SendInput, !fx												; Quit
	BlockInput Off
}
Exit