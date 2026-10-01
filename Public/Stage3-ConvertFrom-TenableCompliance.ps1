function ConvertFrom-TenableCompliance {
    <#
    .SYNOPSIS
        Stage 3. Flattens Tenable (.nessus v2) STIG compliance results to one row per host and check.
    .DESCRIPTION
        Reads cm:compliance-* elements from each ReportItem. STIG ID, Vuln ID, Rule ID and CAT come from
        cm:compliance-reference (pairs such as "STIG-ID|WN22-CC-000010"). If the reference field lacks them,
        the STIG ID and V-ID are pulled by regex from the check name and reference text.
    .EXAMPLE
        ConvertFrom-TenableCompliance -NessusPath .\scan.nessus | Export-Csv tenable.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NessusPath)

    foreach ($file in $NessusPath) {
        if (-not (Test-Path $file)) { throw "Tenable export not found: $file" }
        Write-StigLog "Parsing Tenable export $file"
        $xml = [xml]::new()
        $xml.Load((Resolve-Path $file).ProviderPath)

        foreach ($reportHost in $xml.SelectNodes('//ReportHost')) {
            $tag = { param($n) $node = $reportHost.SelectSingleNode("HostProperties/tag[@name='$n']"); if ($node) { $node.InnerText } }
            $fqdn    = & $tag 'host-fqdn'
            $netbios = & $tag 'netbios-name'
            $ip      = & $tag 'host-ip'
            $scanEnd = & $tag 'HOST_END'
            $hostKey = Get-StigHostKey -NetBiosName $netbios -Fqdn $fqdn -Name $reportHost.GetAttribute('name')

            foreach ($item in $reportHost.SelectNodes('ReportItem')) {
                $cm = { param($n) $node = $item.SelectSingleNode("*[local-name()='compliance-$n']"); if ($node) { $node.InnerText.Trim() } }
                $result = & $cm 'result'
                if (-not $result) { continue }   # not a compliance item

                $checkName = & $cm 'check-name'
                $reference = & $cm 'reference'
                $refs = @{}
                if ($reference) {
                    foreach ($pair in $reference -split ',') {
                        $k, $v = $pair -split '\|', 2
                        if ($v -and -not $refs.ContainsKey($k.Trim())) { $refs[$k.Trim()] = $v.Trim() }
                    }
                }

                $stigId = $refs['STIG-ID']
                if (-not $stigId -and "$checkName $reference" -match $script:StigIdPattern) { $stigId = $Matches[0] }
                $vulnId = $refs['Vuln-ID']
                if (-not $vulnId -and "$checkName $reference" -match $script:VulnIdPattern) { $vulnId = $Matches[0] }
                if ($vulnId -and $vulnId -match $script:VulnIdPattern) { $vulnId = $Matches[0] }

                [pscustomobject]@{
                    HostKey     = $hostKey
                    Fqdn        = $fqdn
                    Ip          = $ip
                    ScanEnd     = $scanEnd
                    CheckName   = $checkName
                    Result      = $result.ToUpperInvariant()
                    ActualValue = & $cm 'actual-value'
                    PolicyValue = & $cm 'policy-value'
                    StigId      = $stigId
                    VulnId      = $vulnId
                    RuleId      = $refs['Rule-ID']
                    Cat         = $refs['CAT']
                    AuditFile   = & $cm 'audit-file'
                    SourceFile  = Split-Path $file -Leaf
                }
            }
        }
    }
}
