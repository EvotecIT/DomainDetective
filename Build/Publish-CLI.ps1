[CmdletBinding()]
param(
    [string] $ConfigPath,
    [string] $Configuration,
    [string] $ArtifactsPath,
    [string] $Version,
    [switch] $SkipRestore,
    [switch] $SkipBuild,
    [switch] $SkipZip,
    [switch] $Plan
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} else {
    Split-Path -Path $PSCommandPath -Parent
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path $scriptRoot 'cli.build.json'
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

function Resolve-SolutionPath {
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Config,

        [Parameter(Mandatory)]
        [string] $RootPath
    )

    $configuredSolutionPath = Get-ConfigValue -Config $Config -Name 'SolutionPath'
    if ($configuredSolutionPath) {
        Join-Path $RootPath ([string] $configuredSolutionPath)
        return
    }

    $solutions = @(Get-ChildItem -LiteralPath $RootPath -Filter '*.sln' -File)
    if ($solutions.Count -eq 1) {
        $solutions[0].FullName
        return
    }

    throw "Unable to resolve a single solution file under $RootPath."
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Build configuration file not found: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$rootPath = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot (Get-ConfigValue -Config $config -Name 'RootPath')))
$solutionPath = Resolve-SolutionPath -Config $config -RootPath $rootPath
$cliProject = Get-ConfigValue -Config $config -Name 'CliProject'
if (-not $cliProject) {
    throw "CliProject is required in $ConfigPath"
}

$cliProjectPath = Join-Path $rootPath ([string] $cliProject)
$effectiveConfiguration = if ($PSBoundParameters.ContainsKey('Configuration') -and $Configuration) { $Configuration } else { [string] (Get-ConfigValue -Config $config -Name 'Configuration') }
$effectiveArtifactsPath = if ($PSBoundParameters.ContainsKey('ArtifactsPath') -and $ArtifactsPath) { $ArtifactsPath } else { [string] (Get-ConfigValue -Config $config -Name 'StagingPath') }
$defaultVersion = Get-ConfigValue -Config $config -Name 'DefaultVersion'
$expectedVersion = Get-ConfigValue -Config $config -Name 'ExpectedVersion'
# X-pattern versions are resolved by PSPublishModule; local wrappers only pass exact versions.
$effectiveVersion = if ($PSBoundParameters.ContainsKey('Version') -and $Version) { $Version } elseif ($defaultVersion) { [string] $defaultVersion } elseif ($expectedVersion -and ([string] $expectedVersion) -notmatch '[Xx]') { [string] $expectedVersion } else { $null }
$cliRootPath = Join-Path $rootPath (Join-Path $effectiveArtifactsPath 'CLI')
$createCliZip = Get-ConfigValue -Config $config -Name 'CreateCliZip'
$cliExecutableBaseName = Get-ConfigValue -Config $config -Name 'CliExecutableBaseName'
$cliRuntimes = @(Get-ConfigValue -Config $config -Name 'CliRuntimes')
$cliAliasMap = Get-ConfigValue -Config $config -Name 'CliAliasMap'
$createZip = if ($SkipZip) { $false } elseif ($null -ne $createCliZip) { [bool] $createCliZip } else { $true }
$executableBaseName = if ($cliExecutableBaseName) { [string] $cliExecutableBaseName } else { [System.IO.Path]::GetFileNameWithoutExtension($cliProjectPath) }

if ($cliRuntimes.Count -eq 0) {
    throw "No CLI runtimes were configured in $ConfigPath"
}

if ($Plan) {
    $runtimePlans = [System.Collections.Generic.List[object]]::new()
    foreach ($runtime in $cliRuntimes) {
        $aliases = @()
        $aliasesProperty = if ($cliAliasMap) { $cliAliasMap.PSObject.Properties[$runtime] } else { $null }
        if ($aliasesProperty) {
            $aliases = @($aliasesProperty.Value)
        }

        $runtimePlans.Add([pscustomobject] @{
                Runtime = [string] $runtime
                Aliases = $aliases
            })
    }

    [pscustomobject] @{
        Type = 'CLI'
        RootPath = $rootPath
        SolutionPath = $solutionPath
        CliProject = $cliProjectPath
        Configuration = $effectiveConfiguration
        OutputPath = $cliRootPath
        Version = $effectiveVersion
        SkipRestore = $SkipRestore.IsPresent
        SkipBuild = $SkipBuild.IsPresent
        CreateZip = $createZip
        Runtimes = $runtimePlans
    }
    return
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet was not found in PATH."
}

if (-not (Test-Path -LiteralPath $cliRootPath)) {
    $null = New-Item -ItemType Directory -Path $cliRootPath -Force
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
        }

        & dotnet @buildArguments
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet build failed."
        }
    }

    foreach ($runtime in $cliRuntimes) {
        $runtimeOutputPath = Join-Path $cliRootPath $runtime
        if (Test-Path -LiteralPath $runtimeOutputPath) {
            Remove-Item -LiteralPath $runtimeOutputPath -Recurse -Force
        }
        $null = New-Item -ItemType Directory -Path $runtimeOutputPath -Force

        $publishArguments = [System.Collections.Generic.List[string]]::new()
        $publishArguments.Add('publish')
        $publishArguments.Add($cliProjectPath)
        $publishArguments.Add('--configuration')
        $publishArguments.Add($effectiveConfiguration)
        $publishArguments.Add('--runtime')
        $publishArguments.Add([string] $runtime)
        $publishArguments.Add('--self-contained')
        $publishArguments.Add('false')
        $publishArguments.Add('--output')
        $publishArguments.Add($runtimeOutputPath)
        $publishArguments.Add('/p:PublishSingleFile=false')
        $publishArguments.Add('/p:UseAppHost=true')
        if ($SkipBuild) {
            $publishArguments.Add('--no-build')
        }
        if ($SkipRestore) {
            $publishArguments.Add('--no-restore')
        }
        if ($effectiveVersion) {
            $publishArguments.Add("/p:Version=$effectiveVersion")
        }

        & dotnet @publishArguments
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed for runtime $runtime."
        }

        $sourceExecutableName = if ($runtime -like 'win-*') { "$executableBaseName.exe" } else { $executableBaseName }
        $sourceExecutablePath = Join-Path $runtimeOutputPath $sourceExecutableName
        if (-not (Test-Path -LiteralPath $sourceExecutablePath)) {
            throw "Expected published executable was not found: $sourceExecutablePath"
        }

        $aliasesProperty = if ($cliAliasMap) { $cliAliasMap.PSObject.Properties[$runtime] } else { $null }
        if ($aliasesProperty) {
            foreach ($aliasName in $aliasesProperty.Value) {
                Copy-Item -LiteralPath $sourceExecutablePath -Destination (Join-Path $runtimeOutputPath $aliasName) -Force
            }
        }

        if ($createZip) {
            $zipPath = Join-Path $cliRootPath ("DomainDetective-CLI-{0}.zip" -f $runtime)
            if (Test-Path -LiteralPath $zipPath) {
                Remove-Item -LiteralPath $zipPath -Force
            }
            Compress-Archive -Path (Join-Path $runtimeOutputPath '*') -DestinationPath $zipPath -CompressionLevel Optimal
        }
    }

    Get-ChildItem -LiteralPath $cliRootPath -Recurse | Sort-Object -Property FullName | Select-Object FullName, Length
} finally {
    Pop-Location
}
