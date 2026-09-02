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
            Set-ItResult -Skipped -Because 'packaged ALC artifact is not present; run Module\Build\Build-Module.ps1 -ConfigurationGateMode Build before this regression'
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
`$coreAssembly = `$commandAlc.Assemblies | Where-Object { `$_.GetName().Name -eq 'DomainDetective' } | Select-Object -First 1
if (`$null -eq `$coreAssembly) {
    throw 'DomainDetective core assembly was not loaded in the module AssemblyLoadContext.'
}

`$healthCheckType = `$coreAssembly.GetType('DomainDetective.DomainHealthCheck', `$true)
`$captureOptionsType = `$coreAssembly.GetType('DomainDetective.CertificateInventoryCaptureOptions', `$true)
`$exportDefaultsType = `$commandAssembly.GetType('DomainDetective.PowerShell.ExportDefaults', `$true)
`$spfCmdletType = `$commandAssembly.GetType('DomainDetective.PowerShell.CmdletTestSpfRecord', `$true)
`$healthCheckAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$healthCheckType.Assembly)
`$captureOptionsAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$captureOptionsType.Assembly)
`$exportDefaultsAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$exportDefaultsType.Assembly)
`$spfCmdletAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$spfCmdletType.Assembly)
`$captureOptions = [Activator]::CreateInstance(`$captureOptionsType)
`$spfCmdlet = [Activator]::CreateInstance(`$spfCmdletType)

[pscustomobject]@{
    CommandName = `$command.Name
    CommandAssembly = `$commandAssembly.GetName().Name
    CommandAssemblyPath = `$commandAssembly.Location
    CommandALC = `$commandAlc.Name
    CommandALCIsDefault = [object]::ReferenceEquals(`$commandAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    CoreAssembly = `$coreAssembly.GetName().Name
    CoreAssemblyPath = `$coreAssembly.Location
    HealthCheckType = `$healthCheckType.FullName
    HealthCheckALC = `$healthCheckAlc.Name
    HealthCheckALCIsDefault = [object]::ReferenceEquals(`$healthCheckAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    CaptureOptionsType = `$captureOptionsType.FullName
    CaptureOptionsALC = `$captureOptionsAlc.Name
    CaptureOptionsALCIsDefault = [object]::ReferenceEquals(`$captureOptionsAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    ExportDefaultsType = `$exportDefaultsType.FullName
    ExportDefaultsALC = `$exportDefaultsAlc.Name
    ExportDefaultsALCIsDefault = [object]::ReferenceEquals(`$exportDefaultsAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    SpfCmdletType = `$spfCmdletType.FullName
    SpfCmdletALC = `$spfCmdletAlc.Name
    SpfCmdletALCIsDefault = [object]::ReferenceEquals(`$spfCmdletAlc, [System.Runtime.Loader.AssemblyLoadContext]::Default)
    CaptureOptionsCreated = `$null -ne `$captureOptions
    SpfCmdletCreated = `$null -ne `$spfCmdlet
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
        $result.CoreAssembly | Should -Be 'DomainDetective'
        ($result.CoreAssemblyPath -replace '\\', '/') | Should -BeLike '*/Artefacts/Unpacked/Modules/DomainDetective/Lib/Core/DomainDetective.dll'
        $result.HealthCheckType | Should -Be 'DomainDetective.DomainHealthCheck'
        $result.HealthCheckALC | Should -Be 'DomainDetective'
        $result.HealthCheckALCIsDefault | Should -BeFalse
        $result.CaptureOptionsType | Should -Be 'DomainDetective.CertificateInventoryCaptureOptions'
        $result.CaptureOptionsALC | Should -Be 'DomainDetective'
        $result.CaptureOptionsALCIsDefault | Should -BeFalse
        $result.ExportDefaultsType | Should -Be 'DomainDetective.PowerShell.ExportDefaults'
        $result.ExportDefaultsALC | Should -Be 'DomainDetective'
        $result.ExportDefaultsALCIsDefault | Should -BeFalse
        $result.SpfCmdletType | Should -Be 'DomainDetective.PowerShell.CmdletTestSpfRecord'
        $result.SpfCmdletALC | Should -Be 'DomainDetective'
        $result.SpfCmdletALCIsDefault | Should -BeFalse
        $result.CaptureOptionsCreated | Should -BeTrue
        $result.SpfCmdletCreated | Should -BeTrue
    }

    It 'generates OfficeIMO reports through the packaged module ALC' {
        $packagedModuleRoot = Join-Path $PSScriptRoot '..\Artefacts\Unpacked\Modules'
        $packagedModule = Join-Path $packagedModuleRoot 'DomainDetective'
        $packagedLoader = Join-Path $packagedModule 'Lib\Core\DomainDetective.ModuleLoadContext.dll'
        if ($PSVersionTable.PSEdition -ne 'Core') {
            Set-ItResult -Skipped -Because 'module-scoped AssemblyLoadContext is PowerShell Core-only'
            return
        }

        if (-not (Test-Path -LiteralPath $packagedLoader)) {
            Set-ItResult -Skipped -Because 'packaged ALC artifact is not present; run Module\Build\Build-Module.ps1 -ConfigurationGateMode Build before this regression'
            return
        }

        $moduleRootLiteral = $packagedModuleRoot.Replace("'", "''")
        $reportBase = Join-Path $TestDrive 'packaged-officeimo.output'
        $reportBaseLiteral = $reportBase.Replace("'", "''")
        $script = @"
`$ErrorActionPreference = 'Stop'
`$WarningPreference = 'SilentlyContinue'
`$moduleRoot = '$moduleRootLiteral'
`$env:PSModulePath = `$moduleRoot + [IO.Path]::PathSeparator + `$env:PSModulePath

Import-Module DomainDetective -Force

`$command = Get-Command Export-DDSecurityReport -Module DomainDetective -ErrorAction Stop
`$commandAssembly = `$command.ImplementingType.Assembly
`$commandAlc = [System.Runtime.Loader.AssemblyLoadContext]::GetLoadContext(`$commandAssembly)
`$coreAssembly = `$commandAlc.Assemblies | Where-Object { `$_.GetName().Name -eq 'DomainDetective' } | Select-Object -First 1
if (`$null -eq `$coreAssembly) {
    throw 'DomainDetective core assembly was not loaded in the module AssemblyLoadContext.'
}

`$spfType = `$coreAssembly.GetType('DomainDetective.Views.SpfRecordInfo', `$true)
`$spf = [Activator]::CreateInstance(`$spfType)
`$spf.Subject = 'example.org'
`$spf.Status = 'OK'

@(`$spf) | Export-DDSecurityReport -ExportFormat Word, Excel, MarkdownHtml -ExportPath '$reportBaseLiteral' -OpenReport:`$false | Out-Null
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        $output = pwsh -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join [Environment]::NewLine)

        $wordPath = [IO.Path]::ChangeExtension($reportBase, '.docx')
        $excelPath = [IO.Path]::ChangeExtension($reportBase, '.xlsx')
        $htmlPath = [IO.Path]::ChangeExtension($reportBase, '.html')
        $markdownPath = [IO.Path]::ChangeExtension($reportBase, '.md')

        Test-Path -LiteralPath $wordPath | Should -BeTrue
        Test-Path -LiteralPath $excelPath | Should -BeTrue
        Test-Path -LiteralPath $htmlPath | Should -BeTrue
        Test-Path -LiteralPath $markdownPath | Should -BeTrue

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $wordArchive = [IO.Compression.ZipFile]::OpenRead($wordPath)
        try {
            $wordArchive.GetEntry('word/document.xml') | Should -Not -BeNullOrEmpty
        } finally {
            $wordArchive.Dispose()
        }

        $excelArchive = [IO.Compression.ZipFile]::OpenRead($excelPath)
        try {
            $excelArchive.GetEntry('xl/workbook.xml') | Should -Not -BeNullOrEmpty
        } finally {
            $excelArchive.Dispose()
        }

        Get-Content -LiteralPath $htmlPath -Raw | Should -Match '<!doctype html>'
        Get-Content -LiteralPath $markdownPath -Raw | Should -Match 'Executive Summary'
    }

    It 'generates OfficeIMO reports through the packaged Windows PowerShell module' {
        $windowsPowerShell = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($null -eq $windowsPowerShell) {
            Set-ItResult -Skipped -Because 'Windows PowerShell is unavailable on this platform'
            return
        }

        $packagedModuleRoot = Join-Path $PSScriptRoot '..\Artefacts\Unpacked\Modules'
        $packagedModule = Join-Path $packagedModuleRoot 'DomainDetective'
        $packagedBinary = Join-Path $packagedModule 'Lib\Default\DomainDetective.PowerShell.dll'
        if (-not (Test-Path -LiteralPath $packagedBinary)) {
            Set-ItResult -Skipped -Because 'packaged Windows PowerShell artifact is not present; run Module\Build\Build-Module.ps1 -ConfigurationGateMode Build before this regression'
            return
        }

        $moduleRootLiteral = $packagedModuleRoot.Replace("'", "''")
        $reportBase = Join-Path $TestDrive 'packaged-officeimo-desktop.output'
        $reportBaseLiteral = $reportBase.Replace("'", "''")
        $script = @"
`$ErrorActionPreference = 'Stop'
`$WarningPreference = 'SilentlyContinue'
`$moduleRoot = '$moduleRootLiteral'
`$env:PSModulePath = `$moduleRoot + [IO.Path]::PathSeparator + `$env:PSModulePath

Import-Module DomainDetective -Force

`$command = Get-Command Export-DDSecurityReport -Module DomainDetective -ErrorAction Stop
`$coreAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { `$_.GetName().Name -eq 'DomainDetective' } | Select-Object -First 1
if (`$null -eq `$coreAssembly) {
    throw 'DomainDetective core assembly was not loaded in the Windows PowerShell AppDomain.'
}

`$spfType = `$coreAssembly.GetType('DomainDetective.Views.SpfRecordInfo', `$true)
`$spf = [Activator]::CreateInstance(`$spfType)
`$spf.Subject = 'example.org'
`$spf.Status = 'OK'

@(`$spf) | Export-DDSecurityReport -ExportFormat Word, Excel, MarkdownHtml -ExportPath '$reportBaseLiteral' -OpenReport:`$false | Out-Null
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        $standardOutput = Join-Path $TestDrive 'packaged-officeimo-desktop.stdout.txt'
        $standardError = Join-Path $TestDrive 'packaged-officeimo-desktop.stderr.txt'
        $process = Start-Process -FilePath $windowsPowerShell.Source `
            -ArgumentList '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded `
            -WindowStyle Hidden `
            -RedirectStandardOutput $standardOutput `
            -RedirectStandardError $standardError `
            -Wait `
            -PassThru
        try {
            $output = @(
                if (Test-Path -LiteralPath $standardOutput) {
                    Get-Content -LiteralPath $standardOutput
                }
                if (Test-Path -LiteralPath $standardError) {
                    Get-Content -LiteralPath $standardError
                }
            )
            $process.ExitCode | Should -Be 0 -Because ($output -join [Environment]::NewLine)
        } finally {
            $process.Dispose()
        }

        $wordPath = [IO.Path]::ChangeExtension($reportBase, '.docx')
        $excelPath = [IO.Path]::ChangeExtension($reportBase, '.xlsx')
        $htmlPath = [IO.Path]::ChangeExtension($reportBase, '.html')
        $markdownPath = [IO.Path]::ChangeExtension($reportBase, '.md')

        Test-Path -LiteralPath $wordPath | Should -BeTrue
        Test-Path -LiteralPath $excelPath | Should -BeTrue
        Test-Path -LiteralPath $htmlPath | Should -BeTrue
        Test-Path -LiteralPath $markdownPath | Should -BeTrue

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $wordArchive = [IO.Compression.ZipFile]::OpenRead($wordPath)
        try {
            $wordArchive.GetEntry('word/document.xml') | Should -Not -BeNullOrEmpty
        } finally {
            $wordArchive.Dispose()
        }

        $excelArchive = [IO.Compression.ZipFile]::OpenRead($excelPath)
        try {
            $excelArchive.GetEntry('xl/workbook.xml') | Should -Not -BeNullOrEmpty
        } finally {
            $excelArchive.Dispose()
        }

        Get-Content -LiteralPath $htmlPath -Raw | Should -Match '<!doctype html>'
        Get-Content -LiteralPath $markdownPath -Raw | Should -Match 'Executive Summary'
    }
}
