<#
.SYNOPSIS
    Creates a desktop shortcut that launches the StigCorrelator GUI.
.EXAMPLE
    .\New-StigCorrelatorShortcut.ps1
    .\New-StigCorrelatorShortcut.ps1 -Destination "$env:PUBLIC\Desktop"   # all users (run as admin)
#>
[CmdletBinding()]
param([string]$Destination = [Environment]::GetFolderPath('Desktop'))

$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
$gui  = Join-Path $PSScriptRoot 'Start-StigCorrelatorGui.ps1'
$lnk  = Join-Path $Destination 'StigCorrelator.lnk'

$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($lnk)
$sc.TargetPath       = $pwsh
$sc.Arguments        = "-STA -NoProfile -WindowStyle Hidden -File `"$gui`""
$sc.WorkingDirectory = $PSScriptRoot
$sc.IconLocation     = "$env:SystemRoot\System32\shell32.dll,22"
$sc.Description      = 'Compare a Tenable STIG scan with a GPO backup, correlated by STIG ID'
$sc.Save()
"Created $lnk"
