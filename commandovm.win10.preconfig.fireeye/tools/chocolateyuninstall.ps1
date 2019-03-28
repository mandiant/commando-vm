$ErrorActionPreference = 'Stop'; # stop on all errors

$packageName = 'flarevm'
try {
	$desktopReadme = Join-Path ${Env:USERPROFILE} "Desktop\README.txt"
	Copy-Item $desktopReadme
} catch {
	# pass
}