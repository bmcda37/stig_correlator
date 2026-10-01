function Compare-GpoBackup {
    <#
    .SYNOPSIS
        Compares two GPO backups setting by setting, with optional STIG ID correlation.
    .DESCRIPTION
        Each backup is reduced to one row per setting (registry key and value, security option, user right,
        account policy or audit subcategory), regardless of which GPO sets it, so backups with different
        GPO names compare cleanly. When a backup has several GPOs setting the same value differently, the
        values are joined with ' | ' and InternalConflict is $true.

        With -XccdfPath, each setting gets its STIG ID, V-ID and CAT, and each side gets a STIG evaluation:
        Compliant, Mismatch, Deletes or Unevaluated (setting present, value not checked).

        Change values: 'Different value', 'Only in reference', 'Only in difference', 'Same'.
        'Same' rows are omitted unless -IncludeSame is used.
    .EXAMPLE
        Compare-GpoBackup -ReferencePath D:\GPO\Prod -DifferencePath D:\GPO\DISA -DifferenceExclude '\bDC\b' `
            -XccdfPath .\U_MS_Windows_Server_2022_STIG_V2R10_Manual-xccdf.xml -ReferenceLabel Prod -DifferenceLabel DISA |
            Format-Table Change, StigId, Setting, ReferenceValue, DifferenceValue, ReferenceStig, DifferenceStig
    .EXAMPLE
        # Policy drift between two monthly backups
        Compare-GpoBackup -ReferencePath D:\GPO\2026-09 -DifferencePath D:\GPO\2026-10 | Export-Csv drift.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReferencePath,
        [Parameter(Mandatory)][string]$DifferencePath,
        [string]$XccdfPath,
        [string]$ReferenceLabel = 'Reference',
        [string]$DifferenceLabel = 'Difference',
        [string]$ReferenceExclude,
        [string]$DifferenceExclude,
        [switch]$StigOnly,
        [switch]$IncludeSame
    )

    $rules = @()
    $byKey = @{}
    if ($XccdfPath) {
        $rules = @(Get-StigRuleMap -XccdfPath $XccdfPath)
        foreach ($r in ($rules | Where-Object SettingKey)) {
            $k = $r.SettingKey.ToLowerInvariant()
            if (-not $byKey.ContainsKey($k)) { $byKey[$k] = $r }
        }
    }

    $auditText = @{ '0' = 'No auditing'; '1' = 'Success'; '2' = 'Failure'; '3' = 'Success and Failure' }
    $formatValue = {
        param($s)
        if ($s.Action -eq 'Delete') { return '(deletes value)' }
        if ($s.SettingKey -like 'AuditPolicy|*' -and $auditText.ContainsKey("$($s.Value)")) { return $auditText["$($s.Value)"] }
        "$($s.Value)"
    }

    $buildView = {
        param($Path, $Exclude, $Label)
        $inv = @(Get-GpoSettingInventory -GpoBackupPath $Path)
        if ($Exclude) { $inv = @($inv | Where-Object { $_.GpoName -notmatch $Exclude }) }
        if (-not $inv.Count) { Write-StigLog "No GPO settings found for $Label ($Path)" -Level WARN }
        $eval = @{}
        if ($rules.Count) {
            foreach ($m in (New-GpoStigMap -RuleMap $rules -GpoInventory $inv)) { $eval["$($m.GpoGuid)|$($m.VulnId)"] = $m.Evaluation }
        }
        $view = @{}
        foreach ($g in ($inv | Where-Object SettingKey | Group-Object { $_.SettingKey.ToLowerInvariant() })) {
            $rule = $byKey[$g.Name]
            $values = @($g.Group | ForEach-Object { & $formatValue $_ } | Select-Object -Unique)
            $view[$g.Name] = [pscustomobject]@{
                Setting  = $g.Group[0].Display
                Value    = $values -join ' | '
                Conflict = $values.Count -gt 1
                Gpos     = (@($g.Group | ForEach-Object GpoName | Select-Object -Unique) -join '; ')
                Eval     = if ($rule) { (@($g.Group | ForEach-Object { $eval["$($_.GpoGuid)|$($rule.VulnId)"] } | Where-Object { $_ } | Select-Object -Unique) -join ' | ') }
            }
        }
        $view
    }

    $refView = & $buildView $ReferencePath $ReferenceExclude $ReferenceLabel
    $difView = & $buildView $DifferencePath $DifferenceExclude $DifferenceLabel

    $keys = @(@($refView.Keys) + @($difView.Keys) | Select-Object -Unique)
    $rank = @{ 'Different value' = 1; 'Only in difference' = 2; 'Only in reference' = 3; 'Same' = 4 }

    $rows = foreach ($k in $keys) {
        $x = $refView[$k]; $y = $difView[$k]
        $rule = $byKey[$k]
        if ($StigOnly -and -not $rule) { continue }
        $change = if (-not $y) { 'Only in reference' } elseif (-not $x) { 'Only in difference' }
                  elseif ($x.Value -ne $y.Value) { 'Different value' } else { 'Same' }
        if ($change -eq 'Same' -and -not $IncludeSame) { continue }
        [pscustomobject]@{
            Change           = $change
            StigId           = if ($rule) { $rule.StigId }
            VulnId           = if ($rule) { $rule.VulnId }
            Cat              = if ($rule) { $rule.Cat }
            RuleTitle        = if ($rule) { $rule.Title }
            Setting          = if ($x) { $x.Setting } else { $y.Setting }
            ReferenceValue   = if ($x) { $x.Value }
            DifferenceValue  = if ($y) { $y.Value }
            ReferenceStig    = if ($x) { $x.Eval }
            DifferenceStig   = if ($y) { $y.Eval }
            ReferenceGpos    = if ($x) { $x.Gpos }
            DifferenceGpos   = if ($y) { $y.Gpos }
            InternalConflict = [bool](($x -and $x.Conflict) -or ($y -and $y.Conflict))
            ReferenceLabel   = $ReferenceLabel
            DifferenceLabel  = $DifferenceLabel
            SettingKey       = $k
        }
    }
    $rows | Sort-Object @{ e = { $rank[$_.Change] } }, @{ e = { if ($_.StigId) { 0 } else { 1 } } }, StigId, Setting
}
