$helperRoot = Join-Path $PSScriptRoot 'Private'
. (Join-Path $helperRoot 'Get-BuildConfigValue.ps1')
. (Join-Path $helperRoot 'ConvertTo-BuildArray.ps1')
. (Join-Path $helperRoot 'Resolve-BuildSolutionPath.ps1')
