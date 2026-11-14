Describe 'Public PDF exports' {
    BeforeAll {
        Import-Module -Name "$PSScriptRoot/../DomainDetective.psd1" -Force
        $script:exportDefaultsSnapshot = @{}
        $script:exportDefaultsProperties = [DomainDetective.PowerShell.ExportDefaults].GetProperties()
        foreach ($property in $script:exportDefaultsProperties) {
            if ($property.CanWrite) {
                $script:exportDefaultsSnapshot[$property.Name] = $property.GetValue($null)
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
        $view = [DomainDetective.Views.SpfRecordInfo]::new()
        $view.Subject = 'example.test'
        $view.Check = [DomainDetective.HealthCheckType]::SPF
        $view.Area = [DomainDetective.AnalysisArea]::Mail
        $view.SpfRecord = 'v=spf1 -all'
        $finding = [DomainDetective.Assessment]::new()
        $finding.Severity = [DomainDetective.AssessmentSeverity]::Warning
        $finding.Code = 'SPF.EXPORT.FIXTURE'
        $finding.Message = 'Offline assessment finding survives every format'
        $view.Assessments = [DomainDetective.Assessment[]]@($finding)

        $view | Export-DDSecurityReport -ExportFormat Word, Pdf, Html -ExportPath $path -ErrorAction Stop

        @(Get-ChildItem -LiteralPath $directory -File).Count | Should -Be 3
        $pdfPath = Join-Path $directory 'assessment.pdf'
        $htmlPath = Join-Path $directory 'assessment.html'
        $pdf = [OfficeIMO.Pdf.PdfReadDocument]::Open([System.IO.File]::ReadAllBytes($pdfPath))
        $pdf.ExtractText() | Should -Match 'Offline assessment finding survives every format'
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
        [DomainDetective.PowerShell.ExportDefaults]::Format | Should -Be ([DomainDetective.Reports.ReportFormat]::Pdf)
        $headers = "From: sender@example.test`r`nTo: recipient@example.test`r`nSubject: Offline message fixture`r`n"
        $defaultDirectory = Join-Path $TestDrive 'message-default'
        $defaultPath = Join-Path $defaultDirectory 'message.pdf'
        Get-DDEmailMessageHeaderInfo -HeaderText $headers -ExportPath $defaultPath -ErrorAction Stop | Out-Null
        @(Get-ChildItem -LiteralPath $defaultDirectory -File).Count | Should -Be 1
        $pdf = [OfficeIMO.Pdf.PdfReadDocument]::Open([System.IO.File]::ReadAllBytes($defaultPath))
        $pdf.ExtractText() | Should -Match 'Offline message fixture'

        $batchDirectory = Join-Path $TestDrive 'message-batch'
        Get-DDEmailMessageHeaderInfo -HeaderText $headers -ExportFormat Word, Pdf, Html -ExportPath (Join-Path $batchDirectory 'message.docx') -ErrorAction Stop | Out-Null
        @(Get-ChildItem -LiteralPath $batchDirectory -File).Count | Should -Be 3
        foreach ($name in @('message.docx', 'message.pdf', 'message.html')) {
            Test-Path -LiteralPath (Join-Path $batchDirectory $name) | Should -BeTrue
        }
        $batchPdf = [OfficeIMO.Pdf.PdfReadDocument]::Open([System.IO.File]::ReadAllBytes((Join-Path $batchDirectory 'message.pdf')))
        $batchPdf.ExtractText() | Should -Match 'Offline message fixture'
    }

    It 'rejects an undefined default format without changing the selected Pdf default' {
        Set-DDExportOptions -DefaultFormat Pdf
        { Set-DDExportOptions -DefaultFormat ([DomainDetective.Reports.ReportFormat]2147483647) -ErrorAction Stop } | Should -Throw
        [DomainDetective.PowerShell.ExportDefaults]::Format | Should -Be ([DomainDetective.Reports.ReportFormat]::Pdf)
    }
}
