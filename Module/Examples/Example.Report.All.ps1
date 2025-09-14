<#

Below are concise PowerShell examples for evotec.xyz, evotec.pl, and evo.yt that follow your existing patterns.

  - Setup helper

    $domains = 'evotec.xyz','evotec.pl','evo.yt'
  - SPF only → Word (single composed doc; detailed sections)

    Test-DDEmailSpfRecord -DomainName $domains |
      Export-DDSecurityReport -ExportFormat Word -ExportPath .\Reports -Scope Detailed -OpenReport
  - SPF + DMARC → HTML (input order, only those sections)

    Export-DDSecurityReport -ExportFormat Html -ExportPath .\Reports -DomainOrder Input -SectionOrderMode Custom -SectionOrder SPF,DMARC -OpenReport {
      Test-DDEmailSpfRecord   -DomainName $domains
      Test-DDEmailDmarcRecord -DomainName $domains
    }
  - DKIM only → HTML

    Test-DDEmailDkimRecord -DomainName $domains |
      Export-DDSecurityReport -ExportFormat Html -ExportPath .\Reports -Scope Detailed -OpenReport
  - Email transport pack (TLS-RPT + MTA-STS) → HTML

    Export-DDSecurityReport -ExportFormat Html -ExportPath .\Reports -OpenReport {
      Test-DDEmailTlsRptRecord -DomainName $domains
      foreach ($d in $domains) {
        Test-DDDnsNsRecord     -DomainName $d
        Test-DDDnsSoaRecord    -DomainName $d
        Test-DDDnsCaaRecord    -DomainName $d
        Test-DDDnsSecStatus    -DomainName $d
        Test-DDDnsZoneTransfer -DomainName $d
        Test-DDDnsWildcard     -DomainName $d
      }
    }
  - Mixed core (SPF/DKIM/DMARC + a few DNS) → Excel

    Export-DDSecurityReport -ExportFormat Excel -ExportPath .\Reports -Scope Normal {
      Test-DDEmailSpfRecord   -DomainName $domains
      Test-DDEmailDkimRecord  -DomainName $domains
      Test-DDEmailDmarcRecord -DomainName $domains
      Test-DDDnsNsRecord      -DomainName 'evotec.pl'
      Test-DDDnsSecStatus     -DomainName 'evotec.pl'
    }
    # Note: Excel composition requires .NET 8.0 (we reference OfficeIMO.Excel 0.3.0)
  - Single domain, single section (keeps output minimal)

    Test-DDEmailSpfRecord   -DomainName 'evotec.xyz' |
      Export-DDSecurityReport -ExportFormat Html -ExportPath .\Reports -OpenReport

    Test-DDEmailDmarcRecord -DomainName 'evotec.pl'  |
      Export-DDSecurityReport -ExportFormat Word -ExportPath .\Reports -OpenReport
  - Optional: Provider help in Executive Summary (Word) — more links/badges

    Test-DDEmailSpfRecord   -DomainName $domains
    Test-DDEmailDmarcRecord -DomainName $domains |
      Export-DDSecurityReport -ExportFormat Word -ExportPath .\Reports -Scope Normal `
        -ProviderHelpPreset Detailed -OpenReport

        #>
Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domains = @('evotec.pl', 'evotec.xyz')

Export-DDSecurityReport -ExportFormat Markdown, MarkdownHtml, Word -ExportPath "$PSScriptRoot\Reports" -Scope Detailed {
    Test-DDEmailSpfRecord -DomainName $domains
    Test-DDEmailDkimRecord -DomainName $domains
    Test-DDEmailDmarcRecord -DomainName $domains
    Test-DDDnsNsRecord -DomainName 'evotec.pl'
    Test-DDDnsSecStatus -DomainName 'evotec.pl'
}
