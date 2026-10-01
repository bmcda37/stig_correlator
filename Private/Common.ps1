# Shared helpers for StigCorrelator. Not exported.

$script:StigIdPattern  = '\b[A-Z][A-Z0-9]{1,11}-[A-Z0-9]{2,6}-\d{6}\b'
$script:VulnIdPattern  = '\bV-\d{4,7}\b'
$script:MaxDetailChars = 1500
$script:StigLogPath    = $null   # set per run by Invoke-StigInputCollection

function Write-StigLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message -ErrorAction Continue }
        default { Write-Verbose $Message }
    }
    if (Get-Variable -Name StigLogPath -Scope Script -ValueOnly -ErrorAction SilentlyContinue) { Add-Content -Path $script:StigLogPath -Value $line -Encoding utf8 }
}

function Write-StigJson {
    param([Parameter(Mandatory)]$InputObject, [Parameter(Mandatory)][string]$Path)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 30
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Read-StigJson {
    param([Parameter(Mandatory)][string]$Path)
    Get-Content -Path $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30
}

function ConvertTo-StigHiveName {
    param([string]$Hive)
    switch -Regex ($Hive) {
        '^(HKEY_LOCAL_MACHINE|HKLM|MACHINE)$' { 'HKLM'; break }
        '^(HKEY_CURRENT_USER|HKCU|USER)$'     { 'HKCU'; break }
        '^(HKEY_USERS|HKU)$'                  { 'HKU';  break }
        default                               { $Hive }
    }
}

function ConvertTo-StigRegKey {
    <# Normalized join key: HKLM\software\policies\x|valuename (lower case, single backslashes). #>
    param([string]$Hive, [string]$Path, [string]$ValueName)
    $h = ConvertTo-StigHiveName $Hive
    $p = ($Path -replace '/', '\' -replace '\\{2,}', '\').Trim().Trim('\')
    '{0}\{1}|{2}' -f $h, $p.ToLowerInvariant(), ($ValueName.Trim().Trim('"')).ToLowerInvariant()
}

function Get-StigSeverityCat {
    param([string]$Severity)
    switch ($Severity) { 'high' { 'CAT I' } 'medium' { 'CAT II' } 'low' { 'CAT III' } default { $Severity } }
}

function Get-StigTruncated {
    param([string]$Text, [int]$Max = $script:MaxDetailChars)
    if ([string]::IsNullOrEmpty($Text) -or $Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max) + ' ...[truncated]'
}

function Get-StigHostKey {
    <# Canonical host key: NetBIOS name, else first label of FQDN, else the raw name. Upper case. #>
    param([string]$NetBiosName, [string]$Fqdn, [string]$Name)
    if ($NetBiosName) { return $NetBiosName.Trim().ToUpperInvariant() }
    if ($Fqdn)        { return ($Fqdn.Split('.')[0]).Trim().ToUpperInvariant() }
    if ($Name -and $Name -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return ($Name.Split('.')[0]).ToUpperInvariant() }
    $Name
}

function Read-StigXccdf {
    <# Loads a STIG Manual XCCDF (1.1 or 1.2) and returns benchmark metadata plus raw Group/Rule data. #>
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) { throw "XCCDF not found: $Path" }
    $xml = [xml]::new()
    $xml.PreserveWhitespace = $true
    $xml.Load((Resolve-Path $Path).ProviderPath)

    $root = $xml.DocumentElement
    $ns   = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $ns.AddNamespace('x', $root.NamespaceURI)

    $release = $root.SelectSingleNode("x:plain-text[@id='release-info']", $ns)
    $info = [pscustomobject]@{
        BenchmarkId = $root.GetAttribute('id')
        Title       = $root.SelectSingleNode('x:title', $ns).InnerText
        Version     = $root.SelectSingleNode('x:version', $ns).InnerText
        ReleaseInfo = if ($release) { $release.InnerText } else { $null }
    }

    $rules = foreach ($g in $root.SelectNodes('x:Group', $ns)) {
        $r = $g.SelectSingleNode('x:Rule', $ns)
        if (-not $r) { continue }
        $check = $r.SelectSingleNode('x:check/x:check-content', $ns)
        [pscustomobject]@{
            VulnId       = $g.GetAttribute('id')
            GroupTitle   = $g.SelectSingleNode('x:title', $ns).InnerText
            RuleId       = $r.GetAttribute('id')
            StigId       = $r.SelectSingleNode('x:version', $ns).InnerText
            Severity     = $r.GetAttribute('severity')
            Title        = $r.SelectSingleNode('x:title', $ns).InnerText
            CheckContent = if ($check) { $check.InnerText } else { '' }
        }
    }
    [pscustomobject]@{ Info = $info; Rules = @($rules) }
}

function Set-StigProp {
    <# Sets a property on a PSCustomObject, adding it if the template does not have it. #>
    param($Object, [string]$Name, $Value)
    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
}
