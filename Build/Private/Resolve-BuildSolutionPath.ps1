function Resolve-BuildSolutionPath {
    <#
    .SYNOPSIS
    Resolves the solution file path for a build configuration.

    .DESCRIPTION
    Uses the configured SolutionPath when present, otherwise requires exactly one solution file under the root path.

    .PARAMETER Config
    The parsed build configuration object.

    .PARAMETER RootPath
    The repository root path used to resolve relative solution paths.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Config,

        [Parameter(Mandatory)]
        [string] $RootPath
    )

    $configuredSolutionPath = Get-BuildConfigValue -Config $Config -Name 'SolutionPath'
    if ($configuredSolutionPath) {
        Join-Path $RootPath ([string] $configuredSolutionPath)
        return
    }

    $solutions = @(Get-ChildItem -LiteralPath $RootPath -Filter '*.sln' -File)
    if ($solutions.Count -eq 1) {
        $solutions[0].FullName
        return
    }

    throw "Expected exactly 1 solution file under $RootPath but found $($solutions.Count)."
}
