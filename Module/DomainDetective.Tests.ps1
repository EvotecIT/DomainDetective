$ModuleName = (Get-ChildItem $PSScriptRoot\*.psd1).BaseName
$PrimaryModule = Get-ChildItem -Path $PSScriptRoot -Filter '*.psd1' -Recurse -ErrorAction SilentlyContinue -Depth 1
if (-not $PrimaryModule) {
    throw "Path $PSScriptRoot doesn't contain PSD1 files. Failing tests."
}
if ($PrimaryModule.Count -ne 1) {
    throw 'More than one PSD1 files detected. Failing tests.'
}
$PSDInformation = Import-PowerShellDataFile -Path $PrimaryModule.FullName
$RequiredModules = @(
    'Pester'
    'DomainDetective'
    if ($PSDInformation.RequiredModules) {
        $PSDInformation.RequiredModules
    }
)
foreach ($Module in $RequiredModules) {
    if ($Module -eq 'DomainDetective') {
        continue
    }
    if ($Module -is [System.Collections.IDictionary]) {
        $Exists = Get-Module -ListAvailable -Name $Module.ModuleName
        if (-not $Exists) {
            Write-Warning "$ModuleName - Downloading $($Module.ModuleName) from PSGallery"
            Install-Module -Name $Module.ModuleName -Force -SkipPublisherCheck
        }
    } else {
        $Exists = Get-Module -ListAvailable $Module -ErrorAction SilentlyContinue
        if (-not $Exists) {
            Install-Module -Name $Module -Force -SkipPublisherCheck
        }
    }
}

Write-Host "ModuleName: $ModuleName Version: $($PSDInformation.ModuleVersion)" -ForegroundColor Yellow
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
Write-Host "PowerShell Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Yellow
Write-Host 'Required modules: ' -ForegroundColor Yellow
foreach ($Module in $PSDInformation.RequiredModules) {
    if ($Module -is [System.Collections.IDictionary]) {
        Write-Host "   [>] $($Module.ModuleName) Version: $($Module.ModuleVersion)" -ForegroundColor Green
    } else {
        Write-Host "   [>] $Module" -ForegroundColor Green
    }
}
Write-Host

try {
    Import-Module $PSScriptRoot\*.psd1 -Force -ErrorAction Stop
    Import-Module Pester -Force -ErrorAction Stop
} catch {
    throw "Failed to import module $ModuleName"
}

$Configuration = [PesterConfiguration]::Default
$Configuration.Run.Path = "$PSScriptRoot\Tests"
$Configuration.Run.Exit = $true
$Configuration.Should.ErrorAction = 'Continue'
$Configuration.CodeCoverage.Enabled = $false
$Configuration.Output.Verbosity = 'Detailed'
$Result = Invoke-Pester -Configuration $Configuration
#$result = Invoke-Pester -Script $PSScriptRoot\Tests -Verbose -Output Detailed #-EnableExit

if ($Result.FailedCount -gt 0) {
    throw "$($Result.FailedCount) tests failed."
}
