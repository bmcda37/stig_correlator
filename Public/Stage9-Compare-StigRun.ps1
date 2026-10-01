function Compare-StigRun {
    <#
    .SYNOPSIS
        Stage 9. Compares this run's merged results with a previous run's and writes run-diff.csv.
    .DESCRIPTION
        Change types, keyed on host + V-ID:
          Regression  NotAFinding -> Open
          NewOpen     (absent or Not_Reviewed) -> Open
          Resolved    Open -> NotAFinding
          StatusOther any other status change
          GpoChanged  status unchanged, but the winning GPO or its value changed
          NewHost / RemovedHost   host appears in only one run
    .EXAMPLE
        Compare-StigRun -CurrentRunDir D:\Stig\Runs\20261030-0800 -PreviousRunDir D:\Stig\Runs\20260930-0800
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CurrentRunDir,
        [Parameter(Mandatory)][string]$PreviousRunDir
    )

    $load = { param($d) $p = Join-Path $d 'work/merged.json'; if (-not (Test-Path $p)) { throw "No merged results at $p" }; @(Read-StigJson $p) }
    $cur = & $load $CurrentRunDir
    $prev = & $load $PreviousRunDir

    $prevIdx = @{}; foreach ($r in $prev) { $prevIdx["$($r.HostKey)|$($r.VulnId)"] = $r }
    $curIdx  = @{}; foreach ($r in $cur)  { $curIdx["$($r.HostKey)|$($r.VulnId)"] = $r }
    $prevHosts = @($prev.HostKey | Select-Object -Unique)
    $curHosts  = @($cur.HostKey  | Select-Object -Unique)

    $diff = [Collections.Generic.List[object]]::new()
    foreach ($h in ($curHosts | Where-Object { $_ -notin $prevHosts })) { $diff.Add([pscustomobject]@{ HostKey = $h; Change = 'NewHost' }) }
    foreach ($h in ($prevHosts | Where-Object { $_ -notin $curHosts })) { $diff.Add([pscustomobject]@{ HostKey = $h; Change = 'RemovedHost' }) }

    foreach ($k in $curIdx.Keys) {
        $c = $curIdx[$k]
        if ($c.HostKey -notin $prevHosts) { continue }
        $p = $prevIdx[$k]
        $before = if ($p) { $p.Status } else { 'Absent' }
        $change = if ($before -eq 'NotAFinding' -and $c.Status -eq 'Open') { 'Regression' }
                  elseif ($before -in 'Absent', 'Not_Reviewed' -and $c.Status -eq 'Open') { 'NewOpen' }
                  elseif ($before -eq 'Open' -and $c.Status -eq 'NotAFinding') { 'Resolved' }
                  elseif ($before -ne $c.Status) { 'StatusOther' }
                  elseif ($p -and ("$($p.WinningGpo)" -ne "$($c.WinningGpo)" -or "$($p.WinningGpoValue)" -ne "$($c.WinningGpoValue)")) { 'GpoChanged' }
        if (-not $change) { continue }
        $diff.Add([pscustomobject]@{
            HostKey = $c.HostKey; Change = $change; Cat = $c.Cat; StigId = $c.StigId; VulnId = $c.VulnId; Title = $c.Title
            PreviousStatus = $before; CurrentStatus = $c.Status
            PreviousGpo = $(if ($p) { $p.WinningGpo }); CurrentGpo = $c.WinningGpo
            PreviousGpoValue = $(if ($p) { $p.WinningGpoValue }); CurrentGpoValue = $c.WinningGpoValue
        })
    }

    $order = @{ Regression = 1; NewOpen = 2; GpoChanged = 3; StatusOther = 4; Resolved = 5; NewHost = 6; RemovedHost = 7 }
    $sorted = $diff | Sort-Object @{ e = { $order[$_.Change] } }, HostKey, StigId
    $out = Join-Path $CurrentRunDir 'review/run-diff.csv'
    $cols = 'HostKey', 'Change', 'Cat', 'StigId', 'VulnId', 'Title', 'PreviousStatus', 'CurrentStatus', 'PreviousGpo', 'CurrentGpo', 'PreviousGpoValue', 'CurrentGpoValue'
    if ($diff.Count) {
        @($sorted) | Select-Object $cols | Export-Csv -Path $out -NoTypeInformation -Encoding utf8
    } else {
        Set-Content -Path $out -Value (($cols | ForEach-Object { '"' + $_ + '"' }) -join ',') -Encoding utf8
    }
    [pscustomobject]@{
        DiffPath = $out
        Counts   = $diff | Group-Object Change | ForEach-Object { [pscustomobject]@{ Change = $_.Name; Count = $_.Count } }
    }
}
