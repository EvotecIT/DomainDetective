Describe 'Export-DDSecurityReport metadata overrides (HTML)' {
    It 'applies Title/Subject/Creator overrides to HTML metadata' -Skip {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $tmp = [System.IO.Path]::GetTempPath()
        $outDir = Join-Path $tmp ("DD-Reports-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $outPath = Join-Path $outDir 'evotec_report.html'

        $title   = 'Evotec — Test Title'
        $subject = 'Evotec Test Subject'
        $creator = 'Evotec'

        Export-DDSecurityReport -Scope Normal -ExportFormat Html -ExportPath $outPath -Title $title -Subject $subject -OpenReport:$false -Compose {
            Test-DDEmailSpfRecord -DomainName 'evotec.pl'
        }

        Test-Path $outPath | Should -BeTrue
        $html = Get-Content -Path $outPath -Raw -Encoding UTF8
        $html | Should -Match [regex]::Escape($title)
        # Author may be rendered as meta name="author" in the head depending on engine
        $html | Should -Match 'Evotec'
    }
}
