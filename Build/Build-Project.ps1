[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'project.build.json'),
    [string] $Configuration,
    [string] $ArtifactsPath,
    [string] $Version,
    [switch] $SkipNuGet,
    [switch] $SkipCli,
    [switch] $SkipRestore,
    [switch] $SkipBuild,
    [switch] $SkipZip,
    [switch] $Plan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Build configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$rootPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $config.RootPath))
$effectiveConfiguration = if ($PSBoundParameters.ContainsKey('Configuration') -and $Configuration) { $Configuration } else { [string] $config.Configuration }
$effectiveArtifactsPath = if ($PSBoundParameters.ContainsKey('ArtifactsPath') -and $ArtifactsPath) { $ArtifactsPath } else { [string] $config.StagingPath }
$effectiveVersion = if ($PSBoundParameters.ContainsKey('Version') -and $Version) { $Version } elseif ($config.DefaultVersion) { [string] $config.DefaultVersion } else { $null }
$stagingPath = Join-Path $rootPath $effectiveArtifactsPath
$cleanStaging = if ($null -ne $config.CleanStaging) { [bool] $config.CleanStaging } else { $true }

if ($cleanStaging -and -not $Plan -and (Test-Path -LiteralPath $stagingPath)) {
    Remove-Item -LiteralPath $stagingPath -Recurse -Force
}

if (-not $SkipNuGet) {
    $nugetArguments = @{
        ConfigPath = $ConfigPath
        Configuration = $effectiveConfiguration
        ArtifactsPath = $effectiveArtifactsPath
    }
    if ($effectiveVersion) {
        $nugetArguments.Version = $effectiveVersion
    }
    if ($SkipRestore) {
        $nugetArguments.SkipRestore = $true
    }
    if ($SkipBuild) {
        $nugetArguments.SkipBuild = $true
    }
    if ($Plan) {
        $nugetArguments.Plan = $true
    }

    & (Join-Path $PSScriptRoot 'Build-NuGet.ps1') @nugetArguments
}

if (-not $SkipCli) {
    $cliArguments = @{
        ConfigPath = $ConfigPath
        Configuration = $effectiveConfiguration
        ArtifactsPath = $effectiveArtifactsPath
    }
    if ($effectiveVersion) {
        $cliArguments.Version = $effectiveVersion
    }
    if ($SkipRestore) {
        $cliArguments.SkipRestore = $true
    }
    if ($SkipBuild) {
        $cliArguments.SkipBuild = $true
    }
    if ($SkipZip) {
        $cliArguments.SkipZip = $true
    }
    if ($Plan) {
        $cliArguments.Plan = $true
    }

    & (Join-Path $PSScriptRoot 'Publish-CLI.ps1') @cliArguments
}
