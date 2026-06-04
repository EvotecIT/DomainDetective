Describe 'Packaged AssemblyLoadContext isolation' {
    It 'loads binary cmdlets and core types from the module ALC' {
        $packagedModuleRoot = Join-Path $PSScriptRoot '..\Artefacts\Unpacked\Modules'
        $packagedModule = Join-Path $packagedModuleRoot 'DomainDetective'
        $packagedLoader = Join-Path $packagedModule 'Lib\Core\DomainDetective.ModuleLoadContext.dll'
        if ($PSVersionTable.PSEdition -ne 'Core') {
            Set-ItResult -Skipped -Because 'module-scoped AssemblyLoadContext is PowerShell Core-only'
            return
        }

        if (-not (Test-Path -LiteralPath $packagedLoader)) {
            Set-ItResult -Skipped -Because 'packaged ALC artifact is not present; run Module\Build\Build-Module.ps1 with RefreshPSD1Only=false before this regression'
            return
        }

        $moduleRootLiteral = $packagedModuleRoot.Replace("'", "''")
        $script = @"
`$ErrorActionPreference = 'Stop'
`$WarningPreference = 'SilentlyContinue'
`$moduleRoot = '$moduleRootLiteral'
`$env:PSModulePath = `$moduleRoot + [IO.Path]::PathSeparator + `$env:PSModulePath

Import-Module DomainDetective -Force

`$command = Get-Command Test-DDEmailSpfRecord -Module DomainDetective -ErrorAction Stop
`$commandAssembly = `$command.ImplementingType.Assembly
`$commandAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$commandAssembly)
`$healthCheckAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext([DomainDetective.DomainHealthCheck].Assembly)
`$captureOptionsAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext([DomainDetective.CertificateInventoryCaptureOptions].Assembly)
`$healthCheck = [DomainDetective.DomainHealthCheck]::new()
`$captureOptions = [DomainDetective.CertificateInventoryCaptureOptions]::new()

[pscustomobject]@{
    CommandName = `$command.Name
    CommandAssembly = `$commandAssembly.GetName().Name
    CommandAssemblyPath = `$commandAssembly.Location
    CommandALC = `$commandAlc.Name
    CommandALCIsDefault = [object]::ReferenceEquals(`$commandAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    HealthCheckType = [DomainDetective.DomainHealthCheck].FullName
    HealthCheckALC = `$healthCheckAlc.Name
    HealthCheckALCIsDefault = [object]::ReferenceEquals(`$healthCheckAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    CaptureOptionsType = [DomainDetective.CertificateInventoryCaptureOptions].FullName
    CaptureOptionsALC = `$captureOptionsAlc.Name
    CaptureOptionsALCIsDefault = [object]::ReferenceEquals(`$captureOptionsAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    HealthCheckCreated = `$null -ne `$healthCheck
    CaptureOptionsCreated = `$null -ne `$captureOptions
} | ConvertTo-Json -Compress
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        $output = pwsh -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join [Environment]::NewLine)

        $json = $output | Where-Object { $_ -is [string] -and $_.TrimStart().StartsWith('{') } | Select-Object -Last 1
        $json | Should -Not -BeNullOrEmpty -Because ($output -join [Environment]::NewLine)
        $result = $json | ConvertFrom-Json

        $result.CommandName | Should -Be 'Test-DDEmailSpfRecord'
        $result.CommandAssembly | Should -Be 'DomainDetective.PowerShell'
        ($result.CommandAssemblyPath -replace '\\', '/') | Should -BeLike '*/Artefacts/Unpacked/Modules/DomainDetective/Lib/Core/DomainDetective.PowerShell.dll'
        $result.CommandALC | Should -Be 'DomainDetective'
        $result.CommandALCIsDefault | Should -BeFalse
        $result.HealthCheckType | Should -Be 'DomainDetective.DomainHealthCheck'
        $result.HealthCheckALC | Should -Be 'DomainDetective'
        $result.HealthCheckALCIsDefault | Should -BeFalse
        $result.CaptureOptionsType | Should -Be 'DomainDetective.CertificateInventoryCaptureOptions'
        $result.CaptureOptionsALC | Should -Be 'DomainDetective'
        $result.CaptureOptionsALCIsDefault | Should -BeFalse
        $result.HealthCheckCreated | Should -BeTrue
        $result.CaptureOptionsCreated | Should -BeTrue
    }
}
