<#
.SYNOPSIS
    Scheduled-task wrapper for the StigCorrelator pipeline.
.DESCRIPTION
    Edit the default paths below or pass parameters. Run on a domain-joined admin host with RSAT
    (GroupPolicy and ActiveDirectory modules) under an account that can read all GPOs.
    Picks the newest previous run automatically for the Stage 9 comparison.
.EXAMPLE
    pwsh -File .\Run-StigPipeline.ps1 -NessusPath D:\Stig\Inbox\srv2022_stig.nessus
#>
[CmdletBinding()]
param(
    [string]$RunRoot          = 'D:\Stig\Runs',
    [string]$XccdfPath        = 'D:\Stig\Reference\U_MS_Windows_Server_2022_STIG_Manual-xccdf.xml',
    [string]$CklbTemplatePath = 'D:\Stig\Reference\WinSrv2022_blank.cklb',
    [Parameter(Mandatory)][string[]]$NessusPath,
    [string]$ScopeOverrideCsv,
    [string]$GpoBackupPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'StigCorrelator.psd1') -Force

$previous = Get-ChildItem -Path $RunRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName 'work' 'merged.json') } |
    Sort-Object Name -Descending | Select-Object -First 1

$params = @{
    RunRoot = $RunRoot; XccdfPath = $XccdfPath; CklbTemplatePath = $CklbTemplatePath
    NessusPath = $NessusPath; Force = $Force
}
if ($previous)         { $params.PreviousRunDir   = $previous.FullName }
if ($ScopeOverrideCsv) { $params.ScopeOverrideCsv = $ScopeOverrideCsv }
if ($GpoBackupPath)    { $params.GpoBackupPath    = $GpoBackupPath }

$result = Invoke-StigPipeline @params
$result | Select-Object RunId, RunDir, Aligned, Hosts, Rules, GpoMappableRules, RuleTypeCounts, ReviewQueueCount | Format-List
$result.Checklists | Format-Table HostKey, NotAFinding, Open, NotReviewed, UnmatchedTemplateRules -AutoSize
if ($result.DiffCounts) { $result.DiffCounts | Format-Table -AutoSize }
