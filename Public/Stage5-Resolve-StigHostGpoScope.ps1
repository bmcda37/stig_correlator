function Resolve-StigHostGpoScope {
    <#
    .SYNOPSIS
        Stage 5. Determines which GPOs apply to each host, in precedence order.
    .DESCRIPTION
        For each host: Get-ADComputer -> parent OU -> Get-GPInheritance -> InheritedGpoLinks (Order 1 = highest
        precedence). Disabled links are dropped, and GPOs whose computer settings are disabled are dropped.
        Security filtering and WMI filters are NOT evaluated; validate with gpresult /x on sample hosts.

        -ScopeOverrideCsv (columns Host, GpoName, Order) replaces AD lookups for listed hosts. Use it for
        workgroup systems, hosts in other forests, or offline testing.
    .OUTPUTS
        One object per host: HostKey, Resolved, Source, OU, Links (GpoGuid, GpoName, Order, Enforced).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$HostKey,
        [string]$GpoStatusPath,
        [string]$ScopeOverrideCsv,
        [string]$Domain,
        [object[]]$GpoInventory
    )

    $override = @{}
    if ($ScopeOverrideCsv) {
        $nameToGuid = @{}
        foreach ($g in $GpoInventory) { if ($g.GpoName) { $nameToGuid[$g.GpoName.ToLowerInvariant()] = $g.GpoGuid } }
        foreach ($row in (Import-Csv $ScopeOverrideCsv)) {
            $h = $row.Host.Trim().ToUpperInvariant()
            if (-not $override.ContainsKey($h)) { $override[$h] = [Collections.Generic.List[object]]::new() }
            $override[$h].Add([pscustomobject]@{
                GpoGuid = $nameToGuid[$row.GpoName.Trim().ToLowerInvariant()]; GpoName = $row.GpoName.Trim()
                Order = [int]$row.Order; Enforced = $false
            })
        }
    }

    $disabled = @{}
    if ($GpoStatusPath -and (Test-Path $GpoStatusPath)) {
        foreach ($s in (Read-StigJson $GpoStatusPath)) {
            if ($s.GpoStatus -in 'AllSettingsDisabled', 'ComputerSettingsDisabled') { $disabled[$s.GpoGuid] = $s.GpoStatus }
        }
    }

    $needAd = @($HostKey | Where-Object { -not $override.ContainsKey($_) })
    if ($needAd.Count) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
    }
    $ouCache = @{}

    foreach ($h in $HostKey) {
        if ($override.ContainsKey($h)) {
            [pscustomobject]@{ HostKey = $h; Resolved = $true; Source = 'Override CSV'; OU = $null
                               Links = @($override[$h] | Sort-Object Order) }
            continue
        }
        try {
            $adArgs = @{ Identity = $h; ErrorAction = 'Stop' }
            if ($Domain) { $adArgs.Server = $Domain }
            $dn = (Get-ADComputer @adArgs).DistinguishedName
            $ou = $dn.Substring($dn.IndexOf(',') + 1)
            if (-not $ouCache.ContainsKey($ou)) {
                $giArgs = @{ Target = $ou; ErrorAction = 'Stop' }
                if ($Domain) { $giArgs.Domain = $Domain }
                $ouCache[$ou] = @((Get-GPInheritance @giArgs).InheritedGpoLinks | Where-Object Enabled | ForEach-Object {
                    [pscustomobject]@{ GpoGuid = $_.GpoId.Guid.ToLowerInvariant(); GpoName = $_.DisplayName
                                       Order = [int]$_.Order; Enforced = [bool]$_.Enforced }
                } | Where-Object { -not $disabled.ContainsKey($_.GpoGuid) } | Sort-Object Order)
            }
            [pscustomobject]@{ HostKey = $h; Resolved = $true; Source = 'Active Directory'; OU = $ou; Links = $ouCache[$ou] }
        } catch {
            Write-StigLog "Could not resolve GPO scope for ${h}: $($_.Exception.Message)" -Level WARN
            [pscustomobject]@{ HostKey = $h; Resolved = $false; Source = 'Unresolved'; OU = $null; Links = @() }
        }
    }
}
