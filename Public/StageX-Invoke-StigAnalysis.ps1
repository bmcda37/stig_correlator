function Invoke-StigAnalysis {
    <#
    .SYNOPSIS
        Correlates Tenable results with the settings in a GPO backup, by STIG ID. No checklist output.
    .DESCRIPTION
        Runs Stages 3-6 in one call and returns an object with the merged rows plus run statistics.
        Scope 'GpoBackup' (default) treats every included GPO in the backup as applying to every scanned
        host, ranked alphabetically. Scope 'ActiveDirectory' uses each host's real GPO links and falls back
        to the backup scope for hosts that AD can't resolve.
    .EXAMPLE
        $a = Invoke-StigAnalysis -XccdfPath .\xccdf.xml -NessusPath .\scan.nessus -GpoBackupPath .\GPOs -ExcludeGpoPattern '\bDC\b'
        $a.Results | Format-Table StigId, VulnId, TenableResult, GpoState, WinningGpo, WinningGpoValue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$XccdfPath,
        [Parameter(Mandatory)][string[]]$NessusPath,
        [Parameter(Mandatory)][string]$GpoBackupPath,
        [string[]]$IncludeGpoGuid,
        [string]$ExcludeGpoPattern,
        [ValidateSet('GpoBackup', 'ActiveDirectory')][string]$Scope = 'GpoBackup',
        [string]$ScopeOverrideCsv,
        [switch]$IncludeUnchecked
    )

    $tenable = @(ConvertFrom-TenableCompliance -NessusPath $NessusPath)
    if (-not $tenable.Count) { throw 'No compliance results found in the Tenable file(s). Export the STIG compliance scan as .nessus.' }
    $rules = @(Get-StigRuleMap -XccdfPath $XccdfPath)
    $inv   = @(Get-GpoSettingInventory -GpoBackupPath $GpoBackupPath)
    if (-not $inv.Count) { throw "No GPO settings found under $GpoBackupPath. Point to the folder that holds the {GUID} backup folders." }

    if ($IncludeGpoGuid) {
        $keep = [Collections.Generic.HashSet[string]]::new([string[]]($IncludeGpoGuid | ForEach-Object { $_.Trim('{', '}').ToLowerInvariant() }))
        $inv = @($inv | Where-Object { $keep.Contains($_.GpoGuid) })
    }
    if ($ExcludeGpoPattern) { $inv = @($inv | Where-Object { $_.GpoName -notmatch $ExcludeGpoPattern }) }
    $gpoMap = @(New-GpoStigMap -RuleMap $rules -GpoInventory $inv)

    $hosts = @($tenable.HostKey | Select-Object -Unique)
    $i = 0
    $links = @($inv | Sort-Object GpoName, GpoGuid -Unique | ForEach-Object {
        $i++; [pscustomobject]@{ GpoGuid = $_.GpoGuid; GpoName = $_.GpoName; Order = $i; Enforced = $false } })
    $backupScope = { param($h) [pscustomobject]@{ HostKey = $h; Resolved = $true; Source = 'GPO backup'; OU = $null; Links = $links } }

    $hostScope = if ($Scope -eq 'ActiveDirectory') {
        try {
            @(Resolve-StigHostGpoScope -HostKey $hosts -GpoInventory $inv -ScopeOverrideCsv $ScopeOverrideCsv) | ForEach-Object {
                if ($_.Resolved) { $_ } else { Write-StigLog "$($_.HostKey) not resolved in AD; using GPO backup scope" -Level WARN; & $backupScope $_.HostKey }
            }
        } catch {
            Write-StigLog "Active Directory scope unavailable ($($_.Exception.Message)); using GPO backup scope" -Level WARN
            $hosts | ForEach-Object { & $backupScope $_ }
        }
    } else {
        $hosts | ForEach-Object { & $backupScope $_ }
    }
    $hostScope = @($hostScope)

    $merged = @(Merge-StigEvidence -RuleMap $rules -GpoStigMap $gpoMap -TenableResults $tenable -HostScope $hostScope)

    $ruleIds = [Collections.Generic.HashSet[string]]::new([string[]]$rules.StigId)
    $scanIds = @($tenable | Where-Object StigId | Select-Object -ExpandProperty StigId -Unique)
    $matchPct = if ($scanIds.Count) { [math]::Round(100 * @($scanIds | Where-Object { $ruleIds.Contains($_) }).Count / $scanIds.Count, 1) }

    [pscustomobject]@{
        Results             = if ($IncludeUnchecked) { $merged } else { @($merged | Where-Object TenableResult -ne 'NO RESULT') }
        AllResults          = $merged
        Hosts               = $hosts
        TenableChecks       = $tenable.Count
        TenableMatchPercent = $matchPct
        StigRules           = $rules.Count
        GpoCount            = @($inv | Select-Object -ExpandProperty GpoGuid -Unique).Count
        GpoSettings         = $inv.Count
        GpoStigMatches      = $gpoMap.Count
        Scope               = @($hostScope | ForEach-Object { [pscustomobject]@{ HostKey = $_.HostKey; Source = $_.Source } })
    }
}
