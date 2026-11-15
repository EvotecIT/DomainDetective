Describe 'Word composition (Pester)' {
    It 'retains assessed domains and supplied findings' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $originalOpen = [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser
        [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $false
        try {
            $reportPath = Join-Path $TestDrive 'dd-word-report.docx'
            $spf = [DomainDetective.Views.SpfRecordInfo]::new()
            $spf.Subject = 'example.com'
            $spf.Status = 'OK'
            $spf.References = [string[]]@('https://example.com/spf')
            $dmarc = [DomainDetective.Views.DmarcRecordInfo]::new()
            $dmarc.Subject = 'example.com'
            $dmarc.Status = 'Warning'
            $dmarc.WarningCount = 1
            $finding = [DomainDetective.Assessment]::new()
            $finding.Severity = [DomainDetective.AssessmentSeverity]::Warning
            $finding.Code = 'DMARC.EXPORT.FIXTURE'
            $finding.Message = 'Distinct policy finding survives module export'
            $dmarc.Assessments = [DomainDetective.Assessment[]]@($finding)
            $dmarc.References = [string[]]@('https://example.com/dmarc')
            @($spf, $dmarc) | Export-DDSecurityReport -ExportFormat Word -ExportPath $reportPath | Out-Null
            Test-Path -Path $reportPath | Should -BeTrue

            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($reportPath)
            try {
                $docEntry = $zip.Entries | Where-Object { $_.FullName -ieq 'word/document.xml' } | Select-Object -First 1
                $stream = $docEntry.Open()
                try {
                    $reader = [System.IO.StreamReader]::new($stream)
                    try {
                        $xml = $reader.ReadToEnd()
                    } finally {
                        $reader.Dispose()
                    }
                } finally {
                    $stream.Dispose()
                }
            } finally {
                $zip.Dispose()
            }

            $text = ($xml -replace '<[^>]+>', ' ') -replace '\s+', ' '
            $text = $text -replace [char]0x200B, ''
            $text | Should -Match 'example.com'
            $text | Should -Match 'Distinct policy finding survives module export'
            $text | Should -Match 'DMARC.EXPORT.FIXTURE'
        } finally {
            [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $originalOpen
        }
    }
}
