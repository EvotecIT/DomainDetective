Describe 'Public PDF exports' {
    BeforeAll {
        Import-Module -Name "$PSScriptRoot/../DomainDetective.psd1" -Force
        # Use the module's own types without loading duplicate assemblies into the default context.
        $script:coreAssembly = (Get-Command Get-DDDomainFlattenedSpfIp -Module DomainDetective).OutputType[0].Type.Assembly
        $script:libraryDirectory = Split-Path -Path (Get-Command Export-DDSecurityReport -Module DomainDetective).ImplementingType.Assembly.Location -Parent
        $script:formatType = [DomainDetective.PowerShell.ExportDefaults].GetProperty('Format').PropertyType
        $script:exportDefaultsSnapshot = @{}
        $script:exportDefaultsProperties = [DomainDetective.PowerShell.ExportDefaults].GetProperties()
        foreach ($property in $script:exportDefaultsProperties) {
            if ($property.CanWrite) {
                $script:exportDefaultsSnapshot[$property.Name] = $property.GetValue($null)
            }
        }
        function Get-PdfExportText {
            param([string] $Path)
            $readerPath = Join-Path $script:libraryDirectory 'OfficeIMO.Pdf.dll'
            $assemblies = @([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
                    $_.GetName().Name -eq 'OfficeIMO.Pdf' -and $_.Location -eq $readerPath
                })
            if ($assemblies.Count -ne 1) {
                throw 'Expected the PDF reader loaded by the packaged module.'
            }
            $readerType = $assemblies[0].GetType('OfficeIMO.Pdf.PdfDocument', $true)
            $pdf = $readerType::Load($Path)
            try {
                $pdf.ExtractText()
            } finally {
                $pdf.Dispose()
            }
        }
    }

    BeforeEach {
        Set-DDExportOptions -Reset
        [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $false
    }

    AfterAll {
        foreach ($property in $script:exportDefaultsProperties) {
            if ($property.CanWrite) {
                $property.SetValue($null, $script:exportDefaultsSnapshot[$property.Name])
            }
        }
    }

    It 'offers Pdf on every command whose ExportFormat accepts Word' {
        $wordCommands = @(Get-Command -Module DomainDetective | Where-Object {
                $_.Parameters -and $_.Parameters.ContainsKey('ExportFormat') -and
                @($_.Parameters['ExportFormat'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues -contains 'Word'
            })
        $wordCommands.Count | Should -BeGreaterThan 0
        foreach ($command in $wordCommands) {
            $validation = $command.Parameters['ExportFormat'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $validation.ValidValues | Should -Contain 'Pdf'
        }
    }

    It 'exports collected assessment views to Word Pdf and Html with one explicit file stem' {
        $directory = Join-Path $TestDrive 'assessment-batch'
        $path = Join-Path $directory 'assessment.docx'
        $view = [Activator]::CreateInstance($script:coreAssembly.GetType('DomainDetective.Views.SpfRecordInfo', $true))
        $view.Subject = 'example.test'
        $view.Check = 'SPF'
        $view.Area = 'Mail'
        $view.SpfRecord = 'v=spf1 -all'
        $finding = [Activator]::CreateInstance($script:coreAssembly.GetType('DomainDetective.Assessment', $true))
        $finding.Severity = 'Warning'
        $finding.Code = 'SPF.EXPORT.FIXTURE'
        $finding.Message = 'Offline assessment finding survives every format'
        $assessments = [Array]::CreateInstance($finding.GetType(), 1)
        $assessments.SetValue($finding, 0)
        $view.Assessments = $assessments

        $view | Export-DDSecurityReport -ExportFormat Word, Pdf, Html -ExportPath $path -ErrorAction Stop

        @(Get-ChildItem -LiteralPath $directory -File).Count | Should -Be 3
        $pdfPath = Join-Path $directory 'assessment.pdf'
        $htmlPath = Join-Path $directory 'assessment.html'
        Get-PdfExportText -Path $pdfPath | Should -Match 'Offline assessment finding survives every format'
        [System.IO.File]::ReadAllText($htmlPath) | Should -Match 'Offline assessment finding survives every format'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($path)
        try {
            $reader = [System.IO.StreamReader]::new($archive.GetEntry('word/document.xml').Open())
            try {
                $reader.ReadToEnd() | Should -Match 'Offline assessment finding survives every format'
            } finally {
                $reader.Dispose()
            }
        } finally {
            $archive.Dispose()
        }
    }

    It 'uses a Pdf default for offline message analysis and honors an explicit format array' {
        Set-DDExportOptions -DefaultFormat Pdf -ErrorAction Stop
        [DomainDetective.PowerShell.ExportDefaults]::Format.ToString() | Should -Be 'Pdf'
        $headers = "From: sender@example.test`r`nTo: recipient@example.test`r`nSubject: Offline message fixture`r`n"
        $defaultDirectory = Join-Path $TestDrive 'message-default'
        $defaultPath = Join-Path $defaultDirectory 'message.pdf'
        Get-DDEmailMessageHeaderInfo -HeaderText $headers -ExportPath $defaultPath -ErrorAction Stop | Out-Null
        @(Get-ChildItem -LiteralPath $defaultDirectory -File).Count | Should -Be 1
        Get-PdfExportText -Path $defaultPath | Should -Match 'Offline message fixture'

        $batchDirectory = Join-Path $TestDrive 'message-batch'
        Get-DDEmailMessageHeaderInfo -HeaderText $headers -ExportFormat Word, Pdf, Html -ExportPath (Join-Path $batchDirectory 'message.docx') -ErrorAction Stop | Out-Null
        @(Get-ChildItem -LiteralPath $batchDirectory -File).Count | Should -Be 3
        foreach ($name in @('message.docx', 'message.pdf', 'message.html')) {
            Test-Path -LiteralPath (Join-Path $batchDirectory $name) | Should -BeTrue
        }
        Get-PdfExportText -Path (Join-Path $batchDirectory 'message.pdf') | Should -Match 'Offline message fixture'
    }

    It 'rejects an undefined default format without changing the selected Pdf default' {
        Set-DDExportOptions -DefaultFormat Pdf
        $undefined = [Enum]::ToObject($script:formatType, [int]::MaxValue)
        { Set-DDExportOptions -DefaultFormat $undefined -ErrorAction Stop } | Should -Throw
        [DomainDetective.PowerShell.ExportDefaults]::Format.ToString() | Should -Be 'Pdf'
    }
}
