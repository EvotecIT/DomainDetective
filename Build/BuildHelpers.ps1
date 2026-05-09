# Dot-sourced by build scripts; $PSScriptRoot resolves to this helper file's directory.
$helperRoot = Join-Path $PSScriptRoot 'Private'
. (Join-Path $helperRoot 'Get-BuildConfigValue.ps1')
. (Join-Path $helperRoot 'ConvertTo-BuildArray.ps1')
. (Join-Path $helperRoot 'Resolve-BuildSolutionPath.ps1')
