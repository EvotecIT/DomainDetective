[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $CliConfigPath,
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

$scriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Path $PSCommandPath -Parent
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'project.build.json'
}

if (-not $CliConfigPath) {
    $CliConfigPath = Join-Path $scriptRoot 'cli.build.json'
}

function Get-ConfigValue {
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Config,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $property = $Config.PSObject.Properties[$Name]
    if ($null -ne $property) {
        $property.Value
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Build configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$rootPath = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot (Get-ConfigValue -Config $config -Name 'RootPath')))
$effectiveConfiguration = if ($PSBoundParameters.ContainsKey('Configuration') -and $Configuration) { $Configuration } else { [string] (Get-ConfigValue -Config $config -Name 'Configuration') }
$effectiveArtifactsPath = if ($PSBoundParameters.ContainsKey('ArtifactsPath') -and $ArtifactsPath) { $ArtifactsPath } else { [string] (Get-ConfigValue -Config $config -Name 'StagingPath') }
$defaultVersion = Get-ConfigValue -Config $config -Name 'DefaultVersion'
$expectedVersion = Get-ConfigValue -Config $config -Name 'ExpectedVersion'
# X-pattern versions are resolved by PSPublishModule; local wrappers only pass exact versions.
$effectiveVersion = if ($PSBoundParameters.ContainsKey('Version') -and $Version) { $Version } elseif ($defaultVersion) { [string] $defaultVersion } elseif ($expectedVersion -and ([string] $expectedVersion) -notmatch '[Xx]') { [string] $expectedVersion } else { $null }
$stagingPath = Join-Path $rootPath $effectiveArtifactsPath
$cleanStagingValue = Get-ConfigValue -Config $config -Name 'CleanStaging'
$publishNugetValue = Get-ConfigValue -Config $config -Name 'PublishNuget'
$configuredNuGetProjects = Get-ConfigValue -Config $config -Name 'NuGetProjects'
$publishCliValue = Get-ConfigValue -Config $config -Name 'PublishCli'
$planOutputPath = Get-ConfigValue -Config $config -Name 'PlanOutputPath'
$resolvedCliConfigPath = if ([System.IO.Path]::IsPathRooted($CliConfigPath)) {
    [System.IO.Path]::GetFullPath($CliConfigPath)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $scriptRoot $CliConfigPath))
}
$cleanStaging = if ($null -ne $cleanStagingValue) { [bool] $cleanStagingValue } else { $true }
$shouldRunNuGet = if ($null -ne $PublishNuget) { [bool] $PublishNuget } elseif ($configuredNuGetProjects -and $null -ne $publishNugetValue) { [bool] $publishNugetValue } else { $true }
$shouldRunCli = if ($null -ne $PublishCli) { [bool] $PublishCli } elseif ($null -ne $publishCliValue) { [bool] $publishCliValue } else { Test-Path -LiteralPath $resolvedCliConfigPath }
$resolvedPlanPath = if ($PSBoundParameters.ContainsKey('PlanPath') -and $PlanPath) { $PlanPath } elseif ($planOutputPath) { [string] $planOutputPath } else { $null }

if ($SkipNuGet) {
    $shouldRunNuGet = $false
}

if ($SkipCli) {
    $shouldRunCli = $false
}

if ($shouldRunCli -and -not (Test-Path -LiteralPath $resolvedCliConfigPath)) {
    throw "CLI build configuration file not found: $resolvedCliConfigPath"
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
        $nugetPlan = & (Join-Path $scriptRoot 'Build-NuGet.ps1') `
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
        $cliPlan = & (Join-Path $scriptRoot 'Publish-CLI.ps1') `
            -ConfigPath $resolvedCliConfigPath `
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
    & (Join-Path $scriptRoot 'Build-NuGet.ps1') @nugetArguments
}

if ($shouldRunCli) {
    $cliArguments = @{
        ConfigPath = $resolvedCliConfigPath
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
    & (Join-Path $scriptRoot 'Publish-CLI.ps1') @cliArguments
}
