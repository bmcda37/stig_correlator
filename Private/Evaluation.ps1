# Value comparison used by New-GpoStigMap.

function Test-StigExpectedValue {
    param($Rule, $Setting)
    if ($Setting.Action -eq 'Delete') { return 'Deletes' }
    if ($null -eq $Rule.ExpectedValue -or $Rule.MultiValue -or $null -eq $Setting.Value) { return 'Unevaluated' }

    if ($Rule.Operator -eq 'bitand') {
        return $(if (([int]$Setting.Value -band [int]$Rule.ExpectedValue) -ne 0) { 'Compliant' } else { 'Mismatch' })
    }
    if ($Rule.ExpectedValue -is [string]) {
        return $(if ("$($Setting.Value)".Trim() -ieq $Rule.ExpectedValue) { 'Compliant' } else { 'Mismatch' })
    }
    $actual = 0.0
    if (-not [double]::TryParse("$($Setting.Value)", [ref]$actual)) { return 'Unevaluated' }
    $expected = [double]$Rule.ExpectedValue
    $ok = switch ($Rule.Operator) {
        'le'    { $actual -le $expected -and -not ($Rule.ExcludeZero -and $actual -eq 0) }
        'ge'    { $actual -ge $expected }
        default { $actual -eq $expected }
    }
    if ($ok) { 'Compliant' } else { 'Mismatch' }
}
