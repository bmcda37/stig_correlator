function Merge-StigEvidence {
    <#
    .SYNOPSIS
        Stage 6. Joins Tenable results and GPO attribution per host and rule, then applies the decision rules.
    .DESCRIPTION
        Tenable aggregation per host + V-ID: any FAILED -> FAILED; else any WARNING/ERROR -> WARNING; else PASSED.
        GPO state per host + rule (only GPOs linked to the host's OU count):
          Compliant   winning GPO value meets the STIG
          Mismatch    winning GPO value does not meet the STIG (or the GPO deletes the value)
          Configured  a GPO sets the setting but the value could not be evaluated
          None        the rule is GPO-mappable but no applicable GPO sets it
          NotMapped   the XCCDF regex method found no GPO setting for this rule (Manual type)
          Unresolved  the host's GPO scope could not be determined
        Winning GPO = lowest link Order among applicable GPOs that set the setting.
        Status: Tenable PASSED -> NotAFinding, FAILED -> Open, anything else or no result -> Not_Reviewed.
        Not_Applicable is never set automatically.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$RuleMap,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$GpoStigMap,
        [Parameter(Mandatory)][object[]]$TenableResults,
        [Parameter(Mandatory)][object[]]$HostScope,
        [string]$RunId = (Get-Date -Format 'yyyyMMdd-HHmmss')
    )

    $stigToVuln = @{}
    foreach ($r in $RuleMap) { $stigToVuln[$r.StigId] = $r.VulnId }

    # Tenable: host|vulnId -> aggregated result
    $tenable = @{}
    $hostInfo = [ordered]@{}
    foreach ($t in $TenableResults) {
        if (-not $hostInfo.Contains($t.HostKey)) { $hostInfo[$t.HostKey] = $t }
        $vid = if ($t.VulnId) { $t.VulnId } elseif ($t.StigId) { $stigToVuln[$t.StigId] }
        if (-not $vid) { continue }
        $k = "$($t.HostKey)|$vid"
        if (-not $tenable.ContainsKey($k)) { $tenable[$k] = [Collections.Generic.List[object]]::new() }
        $tenable[$k].Add($t)
    }

    $gpoByVuln = $GpoStigMap | Group-Object VulnId -AsHashTable -AsString
    if (-not $gpoByVuln) { $gpoByVuln = @{} }
    $scopeByHost = @{}
    foreach ($s in $HostScope) { $scopeByHost[$s.HostKey] = $s }

    foreach ($hk in $hostInfo.Keys) {
        $hInfo = $hostInfo[$hk]
        $scope = $scopeByHost[$hk]
        $linkOrder = @{}
        if ($scope -and $scope.Resolved) { foreach ($l in $scope.Links) { if ($l.GpoGuid) { $linkOrder[$l.GpoGuid] = $l } } }

        foreach ($rule in $RuleMap) {
            # --- Tenable evidence
            $items = $tenable["$hk|$($rule.VulnId)"]
            $tResult = 'NO RESULT'; $tActual = $null; $tExpected = $null; $scanEnd = $hInfo.ScanEnd
            if ($items) {
                $results = @($items.Result)
                $tResult = if ($results -contains 'FAILED') { 'FAILED' }
                           elseif (@($results | Where-Object { $_ -ne 'PASSED' }).Count) { 'WARNING' }
                           else { 'PASSED' }
                $pick = @($items | Where-Object Result -eq $tResult)[0]
                if (-not $pick) { $pick = $items[0] }
                $tActual = $pick.ActualValue; $tExpected = $pick.PolicyValue
            }

            # --- GPO evidence
            $candidates = @()
            if ($gpoByVuln.ContainsKey($rule.VulnId)) {
                $candidates = @($gpoByVuln[$rule.VulnId] | Where-Object { $linkOrder.ContainsKey($_.GpoGuid) } |
                    Sort-Object { $linkOrder[$_.GpoGuid].Order })
            }
            $winner = $candidates | Select-Object -First 1
            $conflict = @($candidates | ForEach-Object { "$($_.GpoValue)" } | Select-Object -Unique).Count -gt 1

            $gpoState = if ($rule.RuleType -eq 'Manual') { 'NotMapped' }
                        elseif (-not ($scope -and $scope.Resolved)) { 'Unresolved' }
                        elseif (-not $winner) { 'None' }
                        else {
                            switch ($winner.Evaluation) { 'Compliant' { 'Compliant' } 'Mismatch' { 'Mismatch' } 'Deletes' { 'Mismatch' } default { 'Configured' } }
                        }

            # --- Decision rules
            $status = switch ($tResult) { 'PASSED' { 'NotAFinding' } 'FAILED' { 'Open' } default { 'Not_Reviewed' } }
            $gpoName = if ($winner) { $winner.GpoName }
            $action = switch ("$status|$gpoState") {
                'NotAFinding|Compliant'  { "Enforced by GPO '$gpoName'." }
                'NotAFinding|Configured' { "Configured by GPO '$gpoName'; value confirmed by scan." }
                'NotAFinding|Mismatch'   { "Host passes but GPO '$gpoName' sets a non-compliant value. Check for a local or higher-precedence override, then fix the GPO." }
                'NotAFinding|None'       { 'Compliant but not enforced by any GPO (local setting). Drift risk: add the setting to a baseline GPO.' }
                'Open|Compliant'         { "GPO '$gpoName' is compliant but the host is not. Check security filtering, WMI filters, precedence, replication and local overrides (gpresult /h)." }
                'Open|Configured'        { "Review the value in GPO '$gpoName' against the STIG requirement." }
                'Open|Mismatch'          { "Fix the value in GPO '$gpoName'." }
                'Open|None'              { 'No applicable GPO sets this. Add the setting to a baseline GPO.' }
                default {
                    if ($status -eq 'Not_Reviewed') { 'Manual review required.' + $(if ($gpoName) { " GPO '$gpoName' state: $gpoState." }) }
                    elseif ($gpoState -eq 'NotMapped') {
                        'Not GPO-correlated (manual or non-GPO check).' + $(if ($status -eq 'Open') { ' Remediate per the STIG fix text.' })
                    }
                    else { 'GPO scope unresolved for this host; attribution unavailable.' }
                }
            }
            if ($conflict) { $action += ' Conflicting values across applicable GPOs: ' + (($candidates | ForEach-Object { "'$($_.GpoName)'=$($_.GpoValue)" }) -join ', ') + '.' }

            $details = @(
                "Tenable: $tResult" + $(if ($scanEnd) { " (scan end $scanEnd)" })
                if ($items) { "Actual: $(Get-StigTruncated $tActual 600)"; "Expected: $(Get-StigTruncated $tExpected 400)" }
                if ($winner) { "GPO: $gpoState - '$($winner.GpoName)' (link order $($linkOrder[$winner.GpoGuid].Order)) sets $($winner.Setting) = $($winner.GpoValue)" }
                else { "GPO: $gpoState" }
            ) -join "`n"

            [pscustomobject]@{
                HostKey = $hk; Fqdn = $hInfo.Fqdn; Ip = $hInfo.Ip
                VulnId = $rule.VulnId; StigId = $rule.StigId; RuleId = $rule.RuleId; Cat = $rule.Cat; Severity = $rule.Severity
                Title = $rule.Title; RuleType = $rule.RuleType
                TenableResult = $tResult; TenableActual = $tActual; TenableExpected = $tExpected
                GpoState = $gpoState; WinningGpo = $gpoName; WinningGpoValue = $(if ($winner) { "$($winner.GpoValue)" })
                GpoConflict = $conflict; Status = $status; Action = $action
                FindingDetails = Get-StigTruncated $details
                Comments = "$action`nAuto-generated by StigCorrelator run $RunId. Requires reviewer validation."
            }
        }
    }
}
