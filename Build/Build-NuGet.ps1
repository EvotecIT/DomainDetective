[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $Configuration,
    [string] $ArtifactsPath,
    [string] $Version,
    [switch] $SkipRestore,
    [switch] $SkipBuild,
    [switch] $Plan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Path $PSCommandPath -Parent
} else {
    (Get-Location).Path
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'project.build.json'
}

. (Join-Path $scriptRoot 'BuildHelpers.ps1')

function Resolve-NuGetProjects {
    <#
    .SYNOPSIS
    Resolves NuGet project paths from build configuration.

    .DESCRIPTION
    Uses explicit NuGetProjects first and can derive project paths from ExpectedVersionMap when enabled.

    .PARAMETER Config
    The parsed project build configuration.

    .PARAMETER RootPath
    The repository root path used to resolve relative project paths.

    .PARAMETER SourcePath
    The configuration file path used in validation errors.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Config,

        [Parameter(Mandatory)]
        [string] $RootPath,

        [Parameter(Mandatory)]
        [string] $SourcePath
    )

    $configuredProjects = Get-BuildConfigValue -Config $Config -Name 'NuGetProjects'
    if ($configuredProjects) {
        @($configuredProjects)
        return
    }

    $expectedVersionMap = Get-BuildConfigValue -Config $Config -Name 'ExpectedVersionMap'
    $expectedVersionMapAsInclude = Get-BuildConfigValue -Config $Config -Name 'ExpectedVersionMapAsInclude'
    if ($expectedVersionMapAsInclude -and $expectedVersionMap) {
        $projects = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $expectedVersionMap.PSObject.Properties) {
            $projectName = [string] $entry.Name
            # ExpectedVersionMap-derived projects follow the repository convention: <ProjectName>/<ProjectName>.csproj.
            $relativeProjectPath = Join-Path $projectName ($projectName + '.csproj')
            $projectPath = Join-Path $RootPath $relativeProjectPath
            if (-not (Test-Path -LiteralPath $projectPath)) {
                throw "ExpectedVersionMap project '$projectName' was not found at $relativeProjectPath."
            }

            $projects.Add($relativeProjectPath)
        }

        $projects.ToArray()
        return
    }

    throw "No NuGet projects were configured in $SourcePath"
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Build configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$rootPath = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot (Get-BuildConfigValue -Config $config -Name 'RootPath')))
$solutionPath = Resolve-BuildSolutionPath -Config $config -RootPath $rootPath
$effectiveConfiguration = if ($PSBoundParameters.ContainsKey('Configuration') -and $Configuration) { $Configuration } else { [string] (Get-BuildConfigValue -Config $config -Name 'Configuration') }
$effectiveArtifactsPath = if ($PSBoundParameters.ContainsKey('ArtifactsPath') -and $ArtifactsPath) { $ArtifactsPath } else { [string] (Get-BuildConfigValue -Config $config -Name 'StagingPath') }
$defaultVersion = Get-BuildConfigValue -Config $config -Name 'DefaultVersion'
$expectedVersion = Get-BuildConfigValue -Config $config -Name 'ExpectedVersion'
# X-pattern versions are resolved by PSPublishModule; local wrappers only pass exact versions.
$effectiveVersion = if ($PSBoundParameters.ContainsKey('Version') -and $Version) { $Version } elseif ($defaultVersion) { [string] $defaultVersion } elseif ($expectedVersion -and ([string] $expectedVersion) -notmatch '[Xx]') { [string] $expectedVersion } else { $null }
$packageOutputPath = Join-Path $rootPath (Join-Path $effectiveArtifactsPath 'NuGet')
$nugetProjects = @(Resolve-NuGetProjects -Config $config -RootPath $rootPath -SourcePath $ConfigPath)

if ($Plan) {
    [pscustomobject] @{
        Type = 'NuGet'
        RootPath = $rootPath
        SolutionPath = $solutionPath
        Configuration = $effectiveConfiguration
        OutputPath = $packageOutputPath
        Version = $effectiveVersion
        SkipRestore = $SkipRestore.IsPresent
        SkipBuild = $SkipBuild.IsPresent
        Projects = $nugetProjects
    }
    return
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet was not found in PATH."
}

if (-not (Test-Path -LiteralPath $packageOutputPath)) {
    $null = New-Item -ItemType Directory -Path $packageOutputPath -Force
}

Push-Location $rootPath
try {
    if (-not $SkipRestore) {
        & dotnet restore $solutionPath
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet restore failed."
        }
    }

    if (-not $SkipBuild) {
        $buildArguments = [System.Collections.Generic.List[string]]::new()
        $buildArguments.Add('build')
        $buildArguments.Add($solutionPath)
        $buildArguments.Add('--configuration')
        $buildArguments.Add($effectiveConfiguration)
        if (-not $SkipRestore) {
            $buildArguments.Add('--no-restore')
        }
        if ($effectiveVersion) {
            $buildArguments.Add("/p:Version=$effectiveVersion")
            $buildArguments.Add("/p:PackageVersion=$effectiveVersion")
        }

        & dotnet @buildArguments
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet build failed."
        }
    }

    foreach ($project in $nugetProjects) {
        $projectPath = Join-Path $rootPath $project
        $packArguments = [System.Collections.Generic.List[string]]::new()
        $packArguments.Add('pack')
        $packArguments.Add($projectPath)
        $packArguments.Add('--configuration')
        $packArguments.Add($effectiveConfiguration)
        $packArguments.Add('--output')
        $packArguments.Add($packageOutputPath)
        if ($SkipBuild) {
            $packArguments.Add('--no-build')
        }
        if ($SkipRestore) {
            $packArguments.Add('--no-restore')
        }
        if ($effectiveVersion) {
            $packArguments.Add("/p:Version=$effectiveVersion")
            $packArguments.Add("/p:PackageVersion=$effectiveVersion")
        }

        & dotnet @packArguments
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet pack failed for $project."
        }
    }

    Get-ChildItem -LiteralPath $packageOutputPath -Filter *.nupkg | Sort-Object -Property Name | Select-Object Name, Length, FullName
} finally {
    Pop-Location
}
