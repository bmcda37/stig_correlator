function Export-StigReviewQueue {
    <#
    .SYNOPSIS
        Stage 8. Writes the reviewer work queue and a per-host summary.
    .DESCRIPTION
        review-queue.csv holds every row that needs a human decision:
          - Status Open or Not_Reviewed
          - NotAFinding with GpoState None (compliant but not GPO-enforced: drift risk)
          - NotAFinding with GpoState Mismatch (host passes despite a non-compliant GPO)
          - any GPO conflict
        Sorted CAT I first, then Open before Not_Reviewed, then host. Blank columns ReviewerDecision,
        Justification, Reviewer and ReviewDate are for the reviewer. Not_Applicable decisions must be
        recorded here with a justification, then set in STIG Viewer.
        summary.csv holds counts per host by status and CAT, plus GPO attribution counts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$MergedResults,
        [Parameter(Mandatory)][string]$OutDir
    )

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $catRank = @{ 'CAT I' = 1; 'CAT II' = 2; 'CAT III' = 3 }
    $statusRank = @{ Open = 1; Not_Reviewed = 2; NotAFinding = 3 }

    $queue = $MergedResults | Where-Object {
        $_.Status -in 'Open', 'Not_Reviewed' -or
        ($_.Status -eq 'NotAFinding' -and $_.GpoState -in 'None', 'Mismatch') -or
        $_.GpoConflict
    } | Sort-Object @{ e = { $catRank[$_.Cat] } }, @{ e = { $statusRank[$_.Status] } }, HostKey, StigId |
        Select-Object HostKey, Cat, StigId, VulnId, Title, Status, TenableResult, GpoState, WinningGpo, WinningGpoValue,
            GpoConflict, Action, TenableActual, TenableExpected,
            @{ n = 'ReviewerDecision'; e = { '' } }, @{ n = 'Justification'; e = { '' } },
            @{ n = 'Reviewer'; e = { '' } }, @{ n = 'ReviewDate'; e = { '' } }
    $queuePath = Join-Path $OutDir 'review-queue.csv'
    @($queue) | Export-Csv -Path $queuePath -NoTypeInformation -Encoding utf8

    $summary = foreach ($g in ($MergedResults | Group-Object HostKey)) {
        $rows = $g.Group
        $c = { param($f) @($rows | Where-Object $f).Count }
        [pscustomobject]@{
            HostKey          = $g.Name
            Rules            = $rows.Count
            NotAFinding      = & $c { $_.Status -eq 'NotAFinding' }
            Open             = & $c { $_.Status -eq 'Open' }
            NotReviewed      = & $c { $_.Status -eq 'Not_Reviewed' }
            Open_CAT_I       = & $c { $_.Status -eq 'Open' -and $_.Cat -eq 'CAT I' }
            Open_CAT_II      = & $c { $_.Status -eq 'Open' -and $_.Cat -eq 'CAT II' }
            Open_CAT_III     = & $c { $_.Status -eq 'Open' -and $_.Cat -eq 'CAT III' }
            GpoEnforced      = & $c { $_.GpoState -eq 'Compliant' }
            GpoMismatch      = & $c { $_.GpoState -eq 'Mismatch' }
            NotGpoEnforced   = & $c { $_.GpoState -eq 'None' }
            GpoConflicts     = & $c { $_.GpoConflict }
            ScopeUnresolved  = & $c { $_.GpoState -eq 'Unresolved' }
        }
    }
    $summaryPath = Join-Path $OutDir 'summary.csv'
    @($summary) | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding utf8

    [pscustomobject]@{ ReviewQueuePath = $queuePath; QueueCount = @($queue).Count; SummaryPath = $summaryPath; Summary = @($summary) }
}
