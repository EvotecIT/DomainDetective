[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'project.build.json'),
    [string] $Configuration,
    [string] $ArtifactsPath,
    [string] $Version,
    [switch] $SkipRestore,
    [switch] $SkipBuild,
    [switch] $Plan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Build configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$rootPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $config.RootPath))
$solutionPath = Join-Path $rootPath $config.SolutionPath
$effectiveConfiguration = if ($PSBoundParameters.ContainsKey('Configuration') -and $Configuration) { $Configuration } else { [string] $config.Configuration }
$effectiveArtifactsPath = if ($PSBoundParameters.ContainsKey('ArtifactsPath') -and $ArtifactsPath) { $ArtifactsPath } else { [string] $config.StagingPath }
$effectiveVersion = if ($PSBoundParameters.ContainsKey('Version') -and $Version) { $Version } elseif ($config.DefaultVersion) { [string] $config.DefaultVersion } else { $null }
$packageOutputPath = Join-Path $rootPath (Join-Path $effectiveArtifactsPath 'NuGet')

if (-not $config.NuGetProjects -or $config.NuGetProjects.Count -eq 0) {
    throw "No NuGet projects were configured in $ConfigPath"
}

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
        Projects = @($config.NuGetProjects)
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

    foreach ($project in $config.NuGetProjects) {
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
