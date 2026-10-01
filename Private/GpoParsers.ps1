# Parsers for the settings files inside a Backup-GPO folder. Pure PowerShell, no external modules.

function Read-RegistryPolFile {
    <#
      Parses a registry.pol (PReg v1) file.
      Format: 'PReg' + uint32 version, then entries [key;value;type;size;data] with UTF-16LE text.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Hive)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8 -or [Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'PReg') {
        Write-StigLog "Not a valid registry.pol file: $Path" -Level WARN
        return
    }

    $pos = 8
    $readString = {
        $start = $pos
        while ($pos + 1 -lt $bytes.Length -and -not ($bytes[$pos] -eq 0 -and $bytes[$pos + 1] -eq 0)) { $pos += 2 }
        $s = [Text.Encoding]::Unicode.GetString($bytes, $start, $pos - $start)
        $pos += 2   # null terminator
        $s
    }

    while ($pos + 1 -lt $bytes.Length) {
        if ([BitConverter]::ToUInt16($bytes, $pos) -ne 0x5B) { $pos += 2; continue }   # '['
        $pos += 2
        $key = . $readString; $pos += 2                                                # ';'
        $valueName = . $readString; $pos += 2
        $type = [BitConverter]::ToUInt32($bytes, $pos); $pos += 6
        $size = [BitConverter]::ToUInt32($bytes, $pos); $pos += 6
        $dataStart = $pos
        $pos += $size + 2                                                              # data + ']'

        $action = 'Set'
        if ($valueName.StartsWith('**del.', [StringComparison]::OrdinalIgnoreCase)) {
            $action = 'Delete'; $valueName = $valueName.Substring(6)
        } elseif ($valueName.StartsWith('**')) {
            continue    # **delvals., **DeleteKeys, **SecureKey etc. are key-level operations
        }

        $value = switch ($type) {
            { $_ -in 1, 2 } { [Text.Encoding]::Unicode.GetString($bytes, $dataStart, $size).TrimEnd([char]0); break }
            4  { if ($size -ge 4) { [BitConverter]::ToUInt32($bytes, $dataStart) }; break }
            5  { if ($size -ge 4) { $b = $bytes[$dataStart..($dataStart + 3)]; [array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }; break }
            11 { if ($size -ge 8) { [BitConverter]::ToUInt64($bytes, $dataStart) }; break }
            7  { ([Text.Encoding]::Unicode.GetString($bytes, $dataStart, $size).TrimEnd([char]0) -split "`0") -join '; '; break }
            default { if ($size -gt 0) { ($bytes[$dataStart..($dataStart + $size - 1)] | ForEach-Object { $_.ToString('x2') }) -join '' } }
        }
        if ($action -eq 'Delete') { $value = $null }

        $typeName = switch ($type) { 1 { 'REG_SZ' } 2 { 'REG_EXPAND_SZ' } 3 { 'REG_BINARY' } 4 { 'REG_DWORD' } 5 { 'REG_DWORD_BIG_ENDIAN' } 7 { 'REG_MULTI_SZ' } 11 { 'REG_QWORD' } default { "TYPE_$type" } }
        [pscustomobject]@{
            Hive = $Hive; Path = $key; ValueName = $valueName; ValueType = $typeName
            Value = $value; Action = $action; Source = 'registry.pol'
        }
    }
}

function Read-GptTmplInf {
    <# Parses GptTmpl.inf. Returns registry values plus System Access, Privilege Rights and Event Audit entries. #>
    param([Parameter(Mandatory)][string]$Path)

    $section = $null
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith(';')) { continue }
        if ($t -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
        if ($t -notmatch '^(?<k>[^=]+?)\s*=\s*(?<v>.*)$') { continue }
        $k = $Matches.k.Trim(); $v = $Matches.v.Trim()

        switch ($section) {
            'Registry Values' {
                # MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,1
                $idx = $k.LastIndexOf('\')
                $hive, $rest = $k.Substring(0, $idx) -split '\\', 2
                $typeCode, $data = $v -split ',', 2
                $value = switch ($typeCode) {
                    '4'     { [uint32]$data; break }
                    '7'     { ($data -split ',') -join '; '; break }
                    default { $data.Trim('"') }
                }
                [pscustomobject]@{
                    Hive = (ConvertTo-StigHiveName $hive); Path = $rest; ValueName = $k.Substring($idx + 1)
                    ValueType = switch ($typeCode) { '1' { 'REG_SZ' } '3' { 'REG_BINARY' } '4' { 'REG_DWORD' } '7' { 'REG_MULTI_SZ' } default { "TYPE_$typeCode" } }
                    Value = $value; Action = 'Set'; Source = 'GptTmpl.inf'
                }
            }
            'System Access'    { [pscustomobject]@{ SettingKey = "SystemAccess|$k";    Value = $v.Trim('"'); Source = 'GptTmpl.inf' } }
            'Privilege Rights' { [pscustomobject]@{ SettingKey = "PrivilegeRights|$k"; Value = $v;           Source = 'GptTmpl.inf' } }
            'Event Audit'      { [pscustomobject]@{ SettingKey = "EventAudit|$k";      Value = $v;           Source = 'GptTmpl.inf' } }
        }
    }
}

function Read-AuditCsv {
    <# Parses Advanced Audit Policy audit.csv. Setting Value: 0 none, 1 success, 2 failure, 3 both. #>
    param([Parameter(Mandatory)][string]$Path)
    foreach ($row in (Import-Csv -Path $Path)) {
        if (-not $row.Subcategory) { continue }
        [pscustomobject]@{
            SettingKey = 'AuditPolicy|' + ($row.Subcategory -replace '^Audit\s+', '').Trim().ToLowerInvariant()
            Value      = [int]$row.'Setting Value'
            Source     = 'audit.csv'
        }
    }
}

function Read-GppRegistryXml {
    <# Parses Group Policy Preferences Registry.xml items (Update/Create/Replace = set; Delete = delete). #>
    param([Parameter(Mandatory)][string]$Path)
    $xml = [xml](Get-Content -Path $Path -Raw)
    foreach ($p in $xml.SelectNodes("//*[local-name()='Registry']/*[local-name()='Properties']")) {
        $name = $p.GetAttribute('name')
        if (-not $name -or $p.GetAttribute('default') -eq '1') { continue }
        $action = if ($p.GetAttribute('action') -eq 'D') { 'Delete' } else { 'Set' }
        $type   = $p.GetAttribute('type')
        $value  = $p.GetAttribute('value')
        if ($type -eq 'REG_DWORD' -and $value -match '^[0-9A-Fa-f]{1,8}$') { $value = [Convert]::ToUInt32($value, 16) }
        [pscustomobject]@{
            Hive = (ConvertTo-StigHiveName $p.GetAttribute('hive')); Path = $p.GetAttribute('key'); ValueName = $name
            ValueType = $type; Value = $(if ($action -eq 'Delete') { $null } else { $value }); Action = $action; Source = 'GPP Registry.xml'
        }
    }
}

function Read-GpoBackupInfo {
    <# Reads bkupInfo.xml from a Backup-GPO folder: GPO display name and GUID. #>
    param([Parameter(Mandatory)][string]$BackupFolder)
    $info = Join-Path $BackupFolder 'bkupInfo.xml'
    if (-not (Test-Path $info)) {
        # Fallback: gpreport.xml (Backup-GPO also writes it), then the folder name.
        $report = Join-Path $BackupFolder 'gpreport.xml'
        if (-not (Test-Path (Join-Path $BackupFolder 'DomainSysvol'))) { return $null }
        $name = Split-Path $BackupFolder -Leaf
        $guid = $name.Trim('{', '}').ToLowerInvariant()
        if (Test-Path $report) {
            $r = [xml](Get-Content -Path $report -Raw)
            $n = $r.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='Name']")
            $i = $r.SelectSingleNode("/*[local-name()='GPO']/*[local-name()='Identifier']/*[local-name()='Identifier']")
            if ($n) { $name = $n.InnerText }
            if ($i) { $guid = $i.InnerText.Trim('{', '}').ToLowerInvariant() }
        }
        Write-StigLog "No bkupInfo.xml in $BackupFolder; using '$name'" -Level WARN
        return [pscustomobject]@{ GpoName = $name; GpoGuid = $guid }
    }
    $xml = [xml](Get-Content -Path $info -Raw)
    [pscustomobject]@{
        GpoName = $xml.SelectSingleNode("//*[local-name()='GPODisplayName']").InnerText
        GpoGuid = $xml.SelectSingleNode("//*[local-name()='GPOGuid']").InnerText.Trim('{', '}').ToLowerInvariant()
    }
}
