@{
    RootModule        = 'StigCorrelator.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = '5d1f7a52-3c2e-4b8e-9a61-2f0c6e8b4d17'
    Author            = 'GoPivot Solutions - Infrastructure & Compliance'
    CompanyName       = 'GoPivot Solutions'
    Description       = 'Correlates Tenable STIG compliance results with domain GPO settings (XCCDF regex method) and generates STIG Viewer 3 .cklb checklists.'
    PowerShellVersion = '7.2'
    FunctionsToExport = @(
        'Test-StigVersionAlignment'      # Stage 1
        'Invoke-StigInputCollection'     # Stage 2
        'ConvertFrom-TenableCompliance'  # Stage 3
        'Get-StigRuleMap'                # Stage 4a
        'Get-GpoSettingInventory'        # Stage 4b
        'New-GpoStigMap'                 # Stage 4c
        'Resolve-StigHostGpoScope'       # Stage 5
        'Merge-StigEvidence'             # Stage 6
        'Export-StigCklb'                # Stage 7
        'Export-StigReviewQueue'         # Stage 8
        'Compare-StigRun'                # Stage 9
        'Invoke-StigPipeline'            # Orchestrator
        'Invoke-StigAnalysis'            # Scan + GPO correlation only (used by the GUI)
        'Compare-GpoBackup'              # Backup-vs-backup comparison (used by the GUI)
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('STIG', 'DISA', 'GPO', 'Tenable', 'CKLB', 'Compliance') } }
}
