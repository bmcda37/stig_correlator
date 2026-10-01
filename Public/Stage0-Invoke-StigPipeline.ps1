function Invoke-StigPipeline {
    <#
    .SYNOPSIS
        Runs stages 1-9 end to end and writes everything to a dated run folder.
    .EXAMPLE
        Invoke-StigPipeline -RunRoot D:\Stig\Runs `
            -XccdfPath .\U_MS_Windows_Server_2022_STIG_Manual-xccdf.xml `
            -CklbTemplatePath .\WinSrv2022_blank.cklb `
            -NessusPath .\tenable_stig_scan.nessus `
            -PreviousRunDir D:\Stig\Runs\20260901-0800 -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RunRoot,
        [Parameter(Mandatory)][string]$XccdfPath,
        [Parameter(Mandatory)][string]$CklbTemplatePath,
        [Parameter(Mandatory)][string[]]$NessusPath,
        [string]$GpoBackupPath,
        [string]$ScopeOverrideCsv,
        [string]$PreviousRunDir,
        [string]$Domain,
        [ValidateRange(0, 100)][int]$MinTenableMatchPercent = 95,
        [switch]$Force
    )

    # Stage 2 first so every later artifact lands in the run folder (Stage 1 needs parsed inputs).
    $run = Invoke-StigInputCollection -RunRoot $RunRoot -XccdfPath $XccdfPath -CklbTemplatePath $CklbTemplatePath `
        -NessusPath $NessusPath -GpoBackupPath $GpoBackupPath -Domain $Domain
    $work = $run.Dirs.work

    Write-StigLog 'Stage 3: parsing Tenable results'
    $tenable = @(ConvertFrom-TenableCompliance -NessusPath $run.NessusPath)
    $tenable | Export-Csv (Join-Path $work 'tenable.csv') -NoTypeInformation -Encoding utf8
    if (-not $tenable.Count) { throw 'No compliance results found in the Tenable export(s).' }

    Write-StigLog 'Stage 1: checking version alignment'
    $align = Test-StigVersionAlignment -XccdfPath $run.XccdfPath -CklbTemplatePath $run.CklbTemplatePath `
        -TenableResults $tenable -MinTenableMatchPercent $MinTenableMatchPercent
    Write-StigJson -InputObject $align -Path (Join-Path $work 'alignment.json')
    if (-not $align.Aligned -and -not $Force) {
        throw "Version alignment failed (see work\alignment.json). Fix the inputs or rerun with -Force. $($align.Problems -join ' ')"
    }

    Write-StigLog 'Stage 4: building the XCCDF rule map and GPO correlation'
    $ruleMap = @(Get-StigRuleMap -XccdfPath $run.XccdfPath)
    $ruleMap | Export-Csv (Join-Path $work 'rule-map.csv') -NoTypeInformation -Encoding utf8
    $inventory = @(Get-GpoSettingInventory -GpoBackupPath $run.GpoBackupPath)
    $inventory | Export-Csv (Join-Path $work 'gpo-inventory.csv') -NoTypeInformation -Encoding utf8
    $gpoMap = @(New-GpoStigMap -RuleMap $ruleMap -GpoInventory $inventory)
    $gpoMap | Export-Csv (Join-Path $work 'gpo-stig-map.csv') -NoTypeInformation -Encoding utf8

    Write-StigLog 'Stage 5: resolving host GPO scope'
    $hosts = @($tenable.HostKey | Select-Object -Unique)
    $scope = @(Resolve-StigHostGpoScope -HostKey $hosts -GpoStatusPath $run.GpoStatusPath `
        -ScopeOverrideCsv $ScopeOverrideCsv -Domain $Domain -GpoInventory $inventory)
    Write-StigJson -InputObject $scope -Path (Join-Path $work 'host-scope.json')

    Write-StigLog 'Stage 6: merging evidence'
    $merged = @(Merge-StigEvidence -RuleMap $ruleMap -GpoStigMap $gpoMap -TenableResults $tenable -HostScope $scope -RunId $run.RunId)
    Write-StigJson -InputObject $merged -Path (Join-Path $work 'merged.json')
    $merged | Export-Csv (Join-Path $work 'merged.csv') -NoTypeInformation -Encoding utf8

    Write-StigLog 'Stage 7: writing CKLB checklists'
    $cklbs = @(Export-StigCklb -CklbTemplatePath $run.CklbTemplatePath -MergedResults $merged -OutDir $run.Dirs.output)

    Write-StigLog 'Stage 8: writing review queue'
    $review = Export-StigReviewQueue -MergedResults $merged -OutDir $run.Dirs.review

    $diff = $null
    if ($PreviousRunDir) {
        Write-StigLog 'Stage 9: comparing with previous run'
        $diff = Compare-StigRun -CurrentRunDir $run.RunDir -PreviousRunDir $PreviousRunDir
    }

    $mapped = @($ruleMap | Where-Object RuleType -ne 'Manual').Count
    $result = [pscustomobject]@{
        RunId              = $run.RunId
        RunDir             = $run.RunDir
        Aligned            = $align.Aligned
        Hosts              = $hosts.Count
        Rules              = $ruleMap.Count
        GpoMappableRules   = $mapped
        RuleTypeCounts     = ($ruleMap | Group-Object RuleType | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
        ScopeUnresolved    = @($scope | Where-Object { -not $_.Resolved } | ForEach-Object HostKey)
        Checklists         = $cklbs
        ReviewQueueCount   = $review.QueueCount
        DiffCounts         = if ($diff) { $diff.Counts } else { $null }
    }
    Write-StigJson -InputObject $result -Path (Join-Path $run.RunDir 'result.json')
    Write-StigLog "Run $($run.RunId) complete"
    $script:StigLogPath = $null
    $result
}
