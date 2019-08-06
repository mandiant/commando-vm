#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn   ; Enable warnings to assist with detecting common errors.
#WinActivateForce

SendMode Input
SetWorkingDir %A_ScriptDir%
SetKeyDelay, 50

; Handle installation
title = Local Group Policy Editor
Run, C:\Windows\system32\gpedit.msc
WinWait, %title%,,5000
IfWinExist %title%
{
  WinActivate, %title%  
  WinMaximize, %title%

  Sleep, 500
  BlockInput On
  
  Sleep, 500
  SendInput, {down}{down}{down}{down}{right}        ; Administrative Template

  Sleep, 500
  SendInput, {down}{down}{right}                    ; Network

  Sleep, 500
  SendInput, N{down}{down}{down}{right}             ; Network Provider
  
  Sleep, 500
  SendInput, {tab}
  
  Sleep, 500
  SendInput, {Enter}
  
  Sleep, 500
  SendInput, !E
  
  Sleep, 500
  SendInput, {tab}{tab}{tab}{enter}
  
  Sleep, 500
  SendInput, {tab}{tab}
  
  SendInput, \\*
  SendInput, {tab}
  SendInput, RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0
  
  Sleep, 500
  SendInput, !O
  SendInput, {tab}{tab}{Enter}
  
  Sleep, 500
  WinClose
  BlockInput Off
}

Exit,