function Invoke-StigInputCollection {
    <#
    .SYNOPSIS
        Stage 2. Creates a dated run folder, copies the inputs into it, and backs up all domain GPOs.
    .DESCRIPTION
        Run folder layout:
          <RunRoot>\<yyyyMMdd-HHmmss>\
            inputs\   XCCDF, blank CKLB, Tenable .nessus files (copied, never modified)
            gpo\      backups\ (Backup-GPO -All) and gpo-status.json
            work\     intermediate JSON/CSV from stages 3-6
            output\   one .cklb per host
            review\   review queue, summary, run diff
            run.json  paths and parameters; manifest.json with SHA-256 hashes of every input
        Pass -GpoBackupPath to reuse an existing Backup-GPO folder (for example, one exported on a DC)
        instead of running Backup-GPO. That also lets you run the pipeline without the GroupPolicy module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunRoot,
        [Parameter(Mandatory)][string]$XccdfPath,
        [Parameter(Mandatory)][string]$CklbTemplatePath,
        [Parameter(Mandatory)][string[]]$NessusPath,
        [string]$GpoBackupPath,
        [string]$Domain
    )

    $runId  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runDir = $PSCmdlet.GetUnresolvedProviderPathFromPSPath((Join-Path $RunRoot $runId))
    $dirs = [ordered]@{}
    foreach ($d in 'inputs', 'gpo', 'work', 'output', 'review') {
        $dirs[$d] = (New-Item -ItemType Directory -Path (Join-Path $runDir $d) -Force).FullName
    }
    $script:StigLogPath = Join-Path $runDir 'pipeline.log'
    Write-StigLog "Run $runId started in $runDir"

    $copy = { param($src) $dst = Join-Path $dirs.inputs (Split-Path $src -Leaf); Copy-Item -Path $src -Destination $dst -Force; $dst }
    $xccdf = & $copy $XccdfPath
    $cklb  = & $copy $CklbTemplatePath
    $nessus = @($NessusPath | ForEach-Object { & $copy $_ })

    $backupDir = Join-Path $dirs.gpo 'backups'
    if ($GpoBackupPath) {
        Write-StigLog "Copying existing GPO backups from $GpoBackupPath"
        Copy-Item -Path $GpoBackupPath -Destination $backupDir -Recurse -Force
    } else {
        Import-Module GroupPolicy -ErrorAction Stop
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        $gpArgs = @{ All = $true; Path = $backupDir }
        if ($Domain) { $gpArgs.Domain = $Domain }
        Write-StigLog 'Running Backup-GPO -All'
        Backup-GPO @gpArgs | Out-Null
        $statusArgs = @{ All = $true }
        if ($Domain) { $statusArgs.Domain = $Domain }
        $status = Get-GPO @statusArgs | ForEach-Object {
            [pscustomobject]@{ GpoName = $_.DisplayName; GpoGuid = $_.Id.Guid.ToLowerInvariant(); GpoStatus = "$($_.GpoStatus)"; Modified = $_.ModificationTime }
        }
        Write-StigJson -InputObject @($status) -Path (Join-Path $dirs.gpo 'gpo-status.json')
    }

    $manifest = Get-ChildItem -Path $dirs.inputs, $backupDir -Recurse -File | ForEach-Object {
        [pscustomobject]@{ File = $_.FullName.Substring($runDir.Length + 1); Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
    }
    Write-StigJson -InputObject @($manifest) -Path (Join-Path $runDir 'manifest.json')

    $run = [pscustomobject]@{
        RunId = $runId; RunDir = $runDir; Dirs = [pscustomobject]$dirs
        XccdfPath = $xccdf; CklbTemplatePath = $cklb; NessusPath = $nessus
        GpoBackupPath = $backupDir; GpoStatusPath = (Join-Path $dirs.gpo 'gpo-status.json')
        Domain = $Domain; Operator = [Environment]::UserName; Started = (Get-Date).ToString('s')
    }
    Write-StigJson -InputObject $run -Path (Join-Path $runDir 'run.json')
    $run
}
