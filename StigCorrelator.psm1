Set-StrictMode -Version Latest

# Load private helpers first, then one script per pipeline stage.
# The manifest's FunctionsToExport controls what is public.
foreach ($folder in 'Private', 'Public') {
    Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1' -File |
        Sort-Object Name | ForEach-Object { . $_.FullName }
}
