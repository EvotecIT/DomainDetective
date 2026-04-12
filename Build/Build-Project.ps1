[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'project.build.json'),
    [string] $Configuration,
    [string] $ArtifactsPath,
    [string] $Version,
    [Nullable[bool]] $PublishNuget,
    [Nullable[bool]] $PublishCli,
    [switch] $SkipNuGet,
    [switch] $SkipCli,
    [switch] $SkipRestore,
    [switch] $SkipBuild,
    [switch] $SkipZip,
    [switch] $Plan,
    [string] $PlanPath
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
$shouldRunNuGet = if ($null -ne $PublishNuget) { [bool] $PublishNuget } elseif ($null -ne $config.PublishNuget) { [bool] $config.PublishNuget } else { $true }
$shouldRunCli = if ($null -ne $PublishCli) { [bool] $PublishCli } elseif ($null -ne $config.PublishCli) { [bool] $config.PublishCli } else { $true }
$resolvedPlanPath = if ($PSBoundParameters.ContainsKey('PlanPath') -and $PlanPath) { $PlanPath } elseif ($config.PlanOutputPath) { [string] $config.PlanOutputPath } else { $null }

if ($SkipNuGet) {
    $shouldRunNuGet = $false
}

if ($SkipCli) {
    $shouldRunCli = $false
}

if ($Plan) {
    $buildPlan = [ordered]@{
        RootPath = $rootPath
        Configuration = $effectiveConfiguration
        ArtifactsPath = $effectiveArtifactsPath
        Version = $effectiveVersion
        CleanStaging = $cleanStaging
        SkipRestore = $SkipRestore.IsPresent
        SkipBuild = $SkipBuild.IsPresent
        CreateCliZip = -not $SkipZip
        PublishNuget = $shouldRunNuGet
        PublishCli = $shouldRunCli
        Steps = @()
    }

    if ($shouldRunNuGet) {
        $nugetPlan = & (Join-Path $PSScriptRoot 'Build-NuGet.ps1') `
            -ConfigPath $ConfigPath `
            -Configuration $effectiveConfiguration `
            -ArtifactsPath $effectiveArtifactsPath `
            -Version $effectiveVersion `
            -SkipRestore:$SkipRestore.IsPresent `
            -SkipBuild:$SkipBuild.IsPresent `
            -Plan
        $buildPlan.Steps += @($nugetPlan)
    }

    if ($shouldRunCli) {
        $cliPlan = & (Join-Path $PSScriptRoot 'Publish-CLI.ps1') `
            -ConfigPath $ConfigPath `
            -Configuration $effectiveConfiguration `
            -ArtifactsPath $effectiveArtifactsPath `
            -Version $effectiveVersion `
            -SkipRestore:$SkipRestore.IsPresent `
            -SkipBuild:$SkipBuild.IsPresent `
            -SkipZip:$SkipZip.IsPresent `
            -Plan
        $buildPlan.Steps += @($cliPlan)
    }

    $planObject = [pscustomobject] $buildPlan
    $planJson = $planObject | ConvertTo-Json -Depth 10

    if ($resolvedPlanPath) {
        $fullPlanPath = if ([System.IO.Path]::IsPathRooted($resolvedPlanPath)) {
            [System.IO.Path]::GetFullPath($resolvedPlanPath)
        } else {
            [System.IO.Path]::GetFullPath((Join-Path $rootPath $resolvedPlanPath))
        }
        $planDirectory = Split-Path -Path $fullPlanPath -Parent
        if (-not (Test-Path -LiteralPath $planDirectory)) {
            $null = New-Item -ItemType Directory -Path $planDirectory -Force
        }

        Set-Content -LiteralPath $fullPlanPath -Value $planJson -Encoding UTF8
        Write-Host "Build plan written to $fullPlanPath"
    }

    $planObject
    return
}

if ($cleanStaging -and (Test-Path -LiteralPath $stagingPath)) {
    Remove-Item -LiteralPath $stagingPath -Recurse -Force
}

if ($shouldRunNuGet) {
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
    & (Join-Path $PSScriptRoot 'Build-NuGet.ps1') @nugetArguments
}

if ($shouldRunCli) {
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
    & (Join-Path $PSScriptRoot 'Publish-CLI.ps1') @cliArguments
}
