Describe 'Report ordering and composition (Pester)' {
    BeforeAll {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $script:originalOpen = [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser
        [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $false

        Set-Item -Path Function:New-TestViews -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string] $Domain
            )

            $spf = [DomainDetective.Views.SpfRecordInfo]::new()
            $spf.Subject = $Domain
            $spf.Status = 'OK'

            $dmarc = [DomainDetective.Views.DmarcRecordInfo]::new()
            $dmarc.Subject = $Domain
            $dmarc.Status = 'Warning'
            $dmarc.WarningCount = 1

            @($spf, $dmarc)
        }

        Set-Item -Path Function:Get-WordXml -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string] $Path
            )

            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
            try {
                $docEntry = $zip.Entries | Where-Object { $_.FullName -ieq 'word/document.xml' } | Select-Object -First 1
                $stream = $docEntry.Open()
                try {
                    $reader = New-Object System.IO.StreamReader($stream)
                    try {
                        $reader.ReadToEnd()
                    } finally {
                        $reader.Dispose()
                    }
                } finally {
                    $stream.Dispose()
                }
            } finally {
                $zip.Dispose()
            }
        }

        Set-Item -Path Function:Get-WordHeadings -Value {
            param(
                [Parameter(Mandatory = $true)]
                [string] $Path
            )

            $xmlText = Get-WordXml -Path $Path
            [xml] $doc = $xmlText
            $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
            $ns.AddNamespace('w', 'http://schemas.openxmlformats.org/wordprocessingml/2006/main')

            $nodes = $doc.SelectNodes('//w:p[w:pPr/w:pStyle]', $ns)
            $list = New-Object System.Collections.Generic.List[object]
            foreach ($n in $nodes) {
                $styleNode = $n.SelectSingleNode('w:pPr/w:pStyle/@w:val', $ns)
                if ($styleNode -eq $null) {
                    continue
                }
                $style = $styleNode.Value
                $textNodes = $n.SelectNodes('.//w:t', $ns)
                $text = ''
                foreach ($t in $textNodes) {
                    $text += $t.InnerText
                }
                $list.Add([pscustomobject]@{ Style = $style; Text = $text })
            }
            $list
        }
    }

    AfterAll {
        [DomainDetective.PowerShell.ExportDefaults]::OpenInBrowser = $script:originalOpen
        Remove-Item -Path Function:New-TestViews -ErrorAction SilentlyContinue
        Remove-Item -Path Function:Get-WordXml -ErrorAction SilentlyContinue
        Remove-Item -Path Function:Get-WordHeadings -ErrorAction SilentlyContinue
    }

    It 'respects domain and section order in Word composition' {
        $reportPath = Join-Path $TestDrive 'ordering-word.docx'
        $items = @()
        $items += New-TestViews -Domain 'b.example'
        $items += New-TestViews -Domain 'a.example'

        $items | Export-DDSecurityReport -ExportFormat Word -ExportPath $reportPath -DomainOrder Input -SectionOrderMode Custom -SectionOrder DMARC,SPF -OpenReport:$false | Out-Null

        Test-Path -Path $reportPath | Should -BeTrue

        $headings = Get-WordHeadings -Path $reportPath
        $domainHeadings = $headings | Where-Object { $_.Style -eq 'Heading1' -and $_.Text -in @('b.example', 'a.example') } | ForEach-Object { $_.Text }
        $domainHeadings | Should -Be @('b.example', 'a.example')

        $indexB = -1
        $indexA = -1
        for ($i = 0; $i -lt $headings.Count; $i++) {
            if ($headings[$i].Style -eq 'Heading1' -and $headings[$i].Text -eq 'b.example') {
                $indexB = $i
            }
            if ($headings[$i].Style -eq 'Heading1' -and $headings[$i].Text -eq 'a.example') {
                $indexA = $i
                break
            }
        }

        $indexB | Should -BeGreaterThan -1
        $indexA | Should -BeGreaterThan $indexB

        $sectionsB = @()
        for ($i = $indexB + 1; $i -lt $indexA; $i++) {
            if ($headings[$i].Style -eq 'Heading2') {
                $sectionsB += $headings[$i].Text
            }
        }
        $sectionsB | Should -Be @('DMARC', 'SPF')

        $xmlText = Get-WordXml -Path $reportPath
        ([regex]::Matches($xmlText, 'b.example').Count) | Should -BeGreaterThan 1
    }

    It 'respects domain and section order in HTML composition' {
        $reportPath = Join-Path $TestDrive 'ordering-html.html'
        $items = @()
        $items += New-TestViews -Domain 'b.example'
        $items += New-TestViews -Domain 'a.example'

        $items | Export-DDSecurityReport -ExportFormat Html -ExportPath $reportPath -DomainOrder Input -SectionOrderMode Custom -SectionOrder DMARC,SPF -OpenReport:$false | Out-Null

        Test-Path -Path $reportPath | Should -BeTrue

        $html = Get-Content -Path $reportPath -Raw -Encoding UTF8
        $idxDomainB = $html.IndexOf('Mail & DNS - b.example')
        $idxDomainA = $html.IndexOf('Mail & DNS - a.example')
        $idxDomainB | Should -BeGreaterThan -1
        $idxDomainA | Should -BeGreaterThan -1
        $idxDomainB | Should -BeLessThan $idxDomainA

        $idxDmarcB = $html.IndexOf('DMARC (Domain-based Message Authentication', $idxDomainB)
        $idxSpfB = $html.IndexOf('SPF (Sender Policy Framework', $idxDomainB)
        $idxDmarcB | Should -BeGreaterThan $idxDomainB
        $idxSpfB | Should -BeGreaterThan $idxDomainB
        $idxDmarcB | Should -BeLessThan $idxSpfB
        $idxDmarcB | Should -BeLessThan $idxDomainA

        $idxSummary = $html.IndexOf('Overall Grade')
        $idxSummary | Should -BeGreaterThan -1
        $idxSummary | Should -BeLessThan $idxDomainB
    }

    It 'flattens piped arrays for HTML composition' {
        $reportPath = Join-Path $TestDrive 'flattening.html'
        $domain = 'example.com'

        $spf = [DomainDetective.Views.SpfRecordInfo]::new()
        $spf.Subject = $domain
        $spf.Status = 'OK'

        $dmarc = [DomainDetective.Views.DmarcRecordInfo]::new()
        $dmarc.Subject = $domain
        $dmarc.Status = 'OK'

        $mx = [DomainDetective.Views.MxInfo]::new()
        $mx.Subject = $domain
        $mx.Status = 'OK'
        $mx.MxRecordExists = $true

        $spfArr = @($spf)
        $dmarcArr = @($dmarc)
        $mxArr = @($mx)

        $spfArr, $dmarcArr, $mxArr | Export-DDSecurityReport -ExportFormat Html -ExportPath $reportPath -OpenReport:$false | Out-Null

        Test-Path -Path $reportPath | Should -BeTrue
        $html = Get-Content -Path $reportPath -Raw -Encoding UTF8
        $html | Should -Match 'Mail & DNS - example.com'
        $html | Should -Match 'MX \(Mail Exchanger\)'
        $html | Should -Match 'SPF \(Sender Policy Framework\)'
    }
}
