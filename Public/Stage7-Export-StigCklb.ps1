function Export-StigCklb {
    <#
    .SYNOPSIS
        Stage 7. Writes one STIG Viewer 3 .cklb per host from the blank template and the merged results.
    .DESCRIPTION
        For each host the blank template is re-read, so every checklist starts clean. The function:
          - sets target_data host_name, fqdn and ip_address, and a new checklist id and title
          - issues new UUIDs for each STIG and rule so checklists can be imported side by side
          - matches rules on V-ID (group_id) and sets status, finding_details and comments
        Rules with no merged row are left as they are in the template (normally not_reviewed).
        Existing reviewer comments in the template are preserved beneath the generated text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CklbTemplatePath,
        [Parameter(Mandatory)][object[]]$MergedResults,
        [Parameter(Mandatory)][string]$OutDir
    )

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $templateText = Get-Content -Path $CklbTemplatePath -Raw -Encoding utf8
    $statusMap = @{ NotAFinding = 'not_a_finding'; Open = 'open'; Not_Reviewed = 'not_reviewed'; Not_Applicable = 'not_applicable' }

    foreach ($group in ($MergedResults | Group-Object HostKey)) {
        $byVuln = @{}
        foreach ($m in $group.Group) { $byVuln[$m.VulnId] = $m }
        $first = $group.Group[0]

        $ckl = $templateText | ConvertFrom-Json -Depth 50
        Set-StigProp $ckl 'id' ([guid]::NewGuid().ToString())
        Set-StigProp $ckl 'title' "$($group.Name) - $(@($ckl.stigs)[0].display_name)"
        if ($ckl.PSObject.Properties.Name -contains 'target_data' -and $ckl.target_data) {
            Set-StigProp $ckl.target_data 'host_name' $group.Name
            Set-StigProp $ckl.target_data 'fqdn' "$($first.Fqdn)"
            Set-StigProp $ckl.target_data 'ip_address' "$($first.Ip)"
        }

        $counts = @{ not_a_finding = 0; open = 0; not_reviewed = 0; unmatched = 0 }
        foreach ($stig in $ckl.stigs) {
            $stigUuid = [guid]::NewGuid().ToString()
            Set-StigProp $stig 'uuid' $stigUuid
            foreach ($rule in $stig.rules) {
                Set-StigProp $rule 'uuid' ([guid]::NewGuid().ToString())
                Set-StigProp $rule 'stig_uuid' $stigUuid
                $vid = if ("$($rule.group_id)" -match $script:VulnIdPattern) { $Matches[0] }
                $m = if ($vid) { $byVuln[$vid] }
                if (-not $m) { $counts.unmatched++; continue }

                $existing = if ($rule.PSObject.Properties.Name -contains 'comments') { "$($rule.comments)".Trim() }
                Set-StigProp $rule 'status' $statusMap[$m.Status]
                Set-StigProp $rule 'finding_details' $m.FindingDetails
                Set-StigProp $rule 'comments' $(if ($existing) { "$($m.Comments)`n---`n$existing" } else { $m.Comments })
                $counts[$statusMap[$m.Status]]++
            }
        }

        $safeName = $group.Name -replace '[^\w.-]', '_'
        $path = Join-Path $OutDir "$safeName.cklb"
        [IO.File]::WriteAllText($path, ($ckl | ConvertTo-Json -Depth 50 -Compress), [Text.UTF8Encoding]::new($false))
        Write-StigLog "Wrote $path"
        [pscustomobject]@{
            HostKey = $group.Name; Path = $path
            NotAFinding = $counts.not_a_finding; Open = $counts.open; NotReviewed = $counts.not_reviewed
            UnmatchedTemplateRules = $counts.unmatched
        }
    }
}
