Describe 'Word composition (Pester)' {
    It 'renders executive summary headings and references' {
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
            $text | Should -Match 'Executive Summary'
            $text | Should -Match 'Overview'
            $text | Should -Match 'All References'
            $text | Should -Match 'Findings\s*\(W/E\)'
        } finally {
            [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $originalOpen
        }
    }
}
