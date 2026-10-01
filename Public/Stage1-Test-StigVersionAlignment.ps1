function Test-StigVersionAlignment {
    <#
    .SYNOPSIS
        Stage 1. Confirms the XCCDF, the blank CKLB and the Tenable results come from the same STIG release.
    .DESCRIPTION
        Checks three things:
          1. CKLB version/release_info matches the XCCDF version/release-info.
          2. Every V-ID in the CKLB exists in the XCCDF, and vice versa.
          3. At least -MinTenableMatchPercent of Tenable STIG IDs exist in the XCCDF.
        Returns an object with Aligned = $true/$false and the details. Use -ThrowOnMismatch to stop a pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$XccdfPath,
        [Parameter(Mandatory)][string]$CklbTemplatePath,
        [object[]]$TenableResults,
        [string[]]$NessusPath,
        [ValidateRange(0, 100)][int]$MinTenableMatchPercent = 95,
        [switch]$ThrowOnMismatch
    )

    $x = Read-StigXccdf -Path $XccdfPath
    $xVulnIds = [Collections.Generic.HashSet[string]]::new([string[]]$x.Rules.VulnId)
    $xStigIds = [Collections.Generic.HashSet[string]]::new([string[]]$x.Rules.StigId)

    $cklb = Read-StigJson -Path $CklbTemplatePath
    $stig = @($cklb.stigs)[0]
    $cVulnIds = @($stig.rules | ForEach-Object { if ("$($_.group_id)" -match $script:VulnIdPattern) { $Matches[0] } })

    $problems = [Collections.Generic.List[string]]::new()
    if ("$($stig.version)" -ne "$($x.Info.Version)") {
        $problems.Add("CKLB version $($stig.version) does not match XCCDF version $($x.Info.Version).")
    }
    if ($x.Info.ReleaseInfo -and "$($stig.release_info)" -and "$($stig.release_info)" -ne $x.Info.ReleaseInfo) {
        $problems.Add("CKLB release '$($stig.release_info)' does not match XCCDF release '$($x.Info.ReleaseInfo)'.")
    }
    $missingInXccdf = @($cVulnIds | Where-Object { -not $xVulnIds.Contains($_) })
    $cSet = [Collections.Generic.HashSet[string]]::new([string[]]$cVulnIds)
    $missingInCklb = @($x.Rules.VulnId | Where-Object { -not $cSet.Contains($_) })
    if ($missingInXccdf.Count) { $problems.Add("$($missingInXccdf.Count) CKLB V-IDs are not in the XCCDF.") }
    if ($missingInCklb.Count)  { $problems.Add("$($missingInCklb.Count) XCCDF V-IDs are not in the CKLB.") }

    if (-not $TenableResults -and $NessusPath) { $TenableResults = @(ConvertFrom-TenableCompliance -NessusPath $NessusPath) }
    $tenableIds = @($TenableResults | Where-Object StigId | Select-Object -ExpandProperty StigId -Unique)
    $matched = @($tenableIds | Where-Object { $xStigIds.Contains($_) })
    $matchPct = if ($tenableIds.Count) { [math]::Round(100 * $matched.Count / $tenableIds.Count, 1) } else { $null }
    if ($TenableResults -and -not $tenableIds.Count) {
        $problems.Add('No STIG IDs found in the Tenable results. Confirm the scan used a DISA STIG audit file.')
    } elseif ($null -ne $matchPct -and $matchPct -lt $MinTenableMatchPercent) {
        $problems.Add("Only $matchPct% of Tenable STIG IDs exist in the XCCDF (minimum $MinTenableMatchPercent%). The audit file is likely a different STIG release.")
    }

    $result = [pscustomobject]@{
        Aligned              = ($problems.Count -eq 0)
        Problems             = @($problems)
        XccdfBenchmark       = $x.Info.BenchmarkId
        XccdfVersion         = $x.Info.Version
        XccdfRelease         = $x.Info.ReleaseInfo
        CklbStigName         = $stig.stig_name
        CklbVersion          = $stig.version
        CklbRelease          = $stig.release_info
        TenableAuditFiles    = @($TenableResults | Select-Object -ExpandProperty AuditFile -Unique | Where-Object { $_ })
        TenableStigIdCount   = $tenableIds.Count
        TenableMatchPercent  = $matchPct
        TenableUnmatchedIds  = @($tenableIds | Where-Object { -not $xStigIds.Contains($_) } | Select-Object -First 25)
    }

    foreach ($p in $problems) { Write-StigLog $p -Level WARN }
    if ($ThrowOnMismatch -and -not $result.Aligned) { throw "STIG version alignment failed: $($problems -join ' ')" }
    $result
}
