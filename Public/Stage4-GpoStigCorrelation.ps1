function Get-StigRuleMap {
    <#
    .SYNOPSIS
        Stage 4a. Builds the STIG rule map from the Manual XCCDF using the regex method.
    .DESCRIPTION
        For each rule, classifies it and extracts the GPO-relevant setting from the check text:
          Registry      - Registry Hive / Registry Path / Value Name / Value Type / Value lines
          AuditPolicy   - "<Category> >> <Subcategory> - Success|Failure"
          UserRight     - "<display name>" user right  (mapped to Se* constant)
          AccountPolicy - value for "<policy name>"     (mapped to GptTmpl.inf [System Access] key)
          Manual        - no pattern matched; not GPO-correlated
        Registry rules get a parsed expected value and operator (eq, le, ge) so GPO values can be evaluated.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$XccdfPath)

    $x = Read-StigXccdf -Path $XccdfPath
    Write-StigLog ("XCCDF {0} V{1} {2}: {3} rules" -f $x.Info.BenchmarkId, $x.Info.Version, $x.Info.ReleaseInfo, $x.Rules.Count)

    foreach ($r in $x.Rules) {
        $text = ($r.CheckContent -replace "`r", '') + "`n"
        $row = [ordered]@{
            VulnId = $r.VulnId; RuleId = $r.RuleId; StigId = $r.StigId; Severity = $r.Severity
            Cat = (Get-StigSeverityCat $r.Severity); Title = $r.Title
            RuleType = 'Manual'; SettingKey = $null; Hive = $null; RegPath = $null; ValueName = $null
            ValueType = $null; ExpectedRaw = $null; ExpectedValue = $null; Operator = $null
            ExcludeZero = $false; MultiValue = $false
        }

        if ($text -match 'Registry Path:\s*(?<path>[^\n]+?)\s*\n' -and $text -match '(?m)^\s*Value Name:\s*(?<vn>[^\n]+?)\s*$') {
            $vn = $Matches.vn.Trim('"', ' ')
            $null = $text -match 'Registry Path:\s*(?<path>[^\n]+?)\s*\n'; $path = $Matches.path
            $hive = if ($text -match 'Registry Hive:\s*(?<h>HKEY_[A-Z_]+)') { $Matches.h } else { 'HKEY_LOCAL_MACHINE' }
            $row.RuleType   = 'Registry'
            $row.Hive       = ConvertTo-StigHiveName $hive
            $row.RegPath    = $path.Trim().Trim('\')
            $row.ValueName  = $vn
            $row.SettingKey = ConvertTo-StigRegKey -Hive $hive -Path $path -ValueName $vn
            $row.MultiValue = ([regex]::Matches($text, 'Value Name:')).Count -gt 1
            if ($text -match 'Value Type:\s*(?<t>REG_[A-Z_]+)') { $row.ValueType = $Matches.t }
            if ($text -match '(?m)^\s*Value:\s*(?<v>[^\n]+?)\s*$') {
                $raw = $Matches.v
                $row.ExpectedRaw = $raw
                $row.Operator = if ($raw -match 'or less') { 'le' } elseif ($raw -match 'or greater|or more') { 'ge' } else { 'eq' }
                $row.ExcludeZero = $raw -match 'excluding\s+"?0'
                if     ($raw -match '^\s*0x[0-9a-fA-F]+\s*\((?<d>\d+)\)') { $row.ExpectedValue = [uint64]$Matches.d }
                elseif ($raw -match '^\s*0x(?<h>[0-9a-fA-F]+)\b')        { $row.ExpectedValue = [Convert]::ToUInt64($Matches.h, 16) }
                elseif ($raw -match '^\s*(?<d>\d+)\s*($|\()')            { $row.ExpectedValue = [uint64]$Matches.d }
                elseif ($row.ValueType -in 'REG_SZ', 'REG_EXPAND_SZ')     { $row.ExpectedValue = $raw.Trim().Trim('"'); $row.Operator = 'eq' }
            }
        }
        elseif ($text -match '(?<cat>[A-Z][A-Za-z /&-]+?)\s*>>\s*(?<sub>[A-Z][A-Za-z /&-]+?)\s*-\s*(?<sf>Success|Failure)\b') {
            $row.RuleType      = 'AuditPolicy'
            $row.SettingKey    = 'AuditPolicy|' + $Matches.sub.Trim().ToLowerInvariant()
            $row.ExpectedRaw   = '{0} >> {1} - {2}' -f $Matches.cat.Trim(), $Matches.sub.Trim(), $Matches.sf
            $row.ExpectedValue = if ($Matches.sf -eq 'Success') { 1 } else { 2 }
            $row.Operator      = 'bitand'
        }
        elseif ($text -match '"(?<right>[^"]+)"\s+(user\s+)?right' -and $script:UserRightMap.ContainsKey($Matches.right.Trim().ToLowerInvariant())) {
            $row.RuleType    = 'UserRight'
            $row.SettingKey  = 'PrivilegeRights|' + $script:UserRightMap[$Matches.right.Trim().ToLowerInvariant()]
            $row.ExpectedRaw = $Matches.right.Trim()
        }
        else {
            foreach ($name in $script:AccountPolicyMap.Keys) {
                if ($text -match ('"' + [regex]::Escape($name) + ',?"')) {
                    $row.RuleType    = 'AccountPolicy'
                    $row.SettingKey  = 'SystemAccess|' + $script:AccountPolicyMap[$name]
                    $row.ExpectedRaw = $name
                    break
                }
            }
        }
        [pscustomobject]$row
    }
}

function Get-GpoSettingInventory {
    <#
    .SYNOPSIS
        Stage 4b. Inventories every setting in a Backup-GPO folder tree.
    .DESCRIPTION
        Reads registry.pol (Machine and User), GptTmpl.inf, audit.csv and GPP Registry.xml for each backup.
        Registry-type settings get the same normalized SettingKey as Get-StigRuleMap.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$GpoBackupPath)

    if (-not (Test-Path -LiteralPath $GpoBackupPath)) { throw "GPO backup path not found: $GpoBackupPath" }
    # Accept either the folder that holds the {GUID} backup folders, or a single {GUID} backup folder.
    $folders = if (Test-Path -LiteralPath (Join-Path $GpoBackupPath 'DomainSysvol')) { @(Get-Item -LiteralPath $GpoBackupPath) }
               else { @(Get-ChildItem -LiteralPath $GpoBackupPath -Directory) }
    $found = 0
    foreach ($backup in $folders) {
        $meta = Read-GpoBackupInfo -BackupFolder $backup.FullName
        if (-not $meta) { continue }
        $found++
        $gpoRoot = Join-Path $backup.FullName 'DomainSysvol\GPO'
        if (-not (Test-Path $gpoRoot)) { $gpoRoot = Join-Path $backup.FullName 'DomainSysvol/GPO' }

        $settings = [Collections.Generic.List[object]]::new()
        foreach ($scope in 'Machine', 'User') {
            $scopeRoot = Join-Path $gpoRoot $scope
            $hive = if ($scope -eq 'Machine') { 'HKLM' } else { 'HKCU' }
            $pol = Join-Path $scopeRoot 'registry.pol'
            if (Test-Path $pol) { Read-RegistryPolFile -Path $pol -Hive $hive | ForEach-Object { $settings.Add($_) } }
            $gpp = Join-Path $scopeRoot 'Preferences/Registry/Registry.xml'
            if (Test-Path $gpp) { Read-GppRegistryXml -Path $gpp | ForEach-Object { $settings.Add($_) } }
        }
        $inf = Join-Path $gpoRoot 'Machine/microsoft/windows nt/SecEdit/GptTmpl.inf'
        if (Test-Path $inf) { Read-GptTmplInf -Path $inf | ForEach-Object { $settings.Add($_) } }
        $audit = Join-Path $gpoRoot 'Machine/microsoft/windows nt/Audit/audit.csv'
        if (Test-Path $audit) { Read-AuditCsv -Path $audit | ForEach-Object { $settings.Add($_) } }

        foreach ($s in $settings) {
            $isReg = $s.PSObject.Properties.Name -contains 'ValueName'
            [pscustomobject]@{
                GpoName    = $meta.GpoName
                GpoGuid    = $meta.GpoGuid
                Source     = $s.Source
                Scope      = if ($isReg -and $s.Hive -eq 'HKCU') { 'User' } else { 'Computer' }
                SettingKey = if ($isReg) { ConvertTo-StigRegKey -Hive $s.Hive -Path $s.Path -ValueName $s.ValueName } else { $s.SettingKey }
                Display    = if ($isReg) { '{0}\{1}\{2}' -f $s.Hive, $s.Path, $s.ValueName } else { $s.SettingKey }
                ValueType  = if ($isReg) { $s.ValueType } else { $null }
                Value      = $s.Value
                Action     = if ($isReg) { $s.Action } else { 'Set' }
            }
        }
    }
    if (-not $found) { Write-StigLog "No GPO backups found under $GpoBackupPath" -Level WARN }
}

function New-GpoStigMap {
    <#
    .SYNOPSIS
        Stage 4c. Joins the STIG rule map to the GPO inventory on SettingKey and evaluates each match.
    .OUTPUTS
        One row per (rule, GPO) pair. Evaluation: Compliant | Mismatch | Deletes | Unevaluated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$RuleMap,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$GpoInventory
    )

    $index = @{}
    foreach ($g in $GpoInventory) {
        if (-not $g.SettingKey) { continue }
        $k = $g.SettingKey.ToLowerInvariant()
        if (-not $index.ContainsKey($k)) { $index[$k] = [Collections.Generic.List[object]]::new() }
        $index[$k].Add($g)
    }

    foreach ($rule in ($RuleMap | Where-Object SettingKey)) {
        $hits = $index[$rule.SettingKey.ToLowerInvariant()]
        if (-not $hits) { continue }
        foreach ($g in $hits) {
            [pscustomobject]@{
                VulnId     = $rule.VulnId
                StigId     = $rule.StigId
                RuleType   = $rule.RuleType
                GpoName    = $g.GpoName
                GpoGuid    = $g.GpoGuid
                Scope      = $g.Scope
                Source     = $g.Source
                Setting    = $g.Display
                GpoValue   = $g.Value
                Expected   = $rule.ExpectedRaw
                Evaluation = Test-StigExpectedValue -Rule $rule -Setting $g
            }
        }
    }
}
