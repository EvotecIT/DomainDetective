Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Multi-domain HTML dashboard showcasing most report sections end-to-end.
# Note: Results vary over time as DNS and provider configurations change.
$domains = @('evotec.pl', 'evotec.xyz', 'cyberdrain.com')
$dkimSelectors = @('s1', 's2')
$reportPath = Join-Path -Path $PSScriptRoot -ChildPath 'Reports'

Export-DDSecurityReport -ExportFormat Html -ExportPath $reportPath -Scope Detailed -DomainOrder Input -SectionOrderMode Custom `
    -SectionOrder MX, SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, DNSBL, DNSSEC, DANE, RPKI, NS, SOA, CAA, TTL, ZoneTransfer, Wildcard, Classification, MAILTLS `
    -OpenInBrowser -Compose {
    Test-DDEmailSpfRecord -DomainName $domains
    Test-DDEmailDkimRecord -DomainName $domains -Selectors $dkimSelectors -FullResponse
    Test-DDEmailDmarcRecord -DomainName $domains
    Test-DDEmailTlsRptRecord -DomainName $domains

    Test-DDDnsBlacklist -NameOrIpAddress $domains -TreatAsDomain -FullResponse
    Test-DDRpki -DomainName $domains
    Test-DDMailDomainClassification -DomainName $domains

    Test-DDDnsMxRecord -DomainName $domains
    Test-DDDnsNsRecord -DomainName $domains
    Test-DDDnsSoaRecord -DomainName $domains
    Test-DDDnsCaaRecord -DomainName $domains
    Test-DDDnsSecStatus -DomainName $domains
    Test-DDTlsDaneRecord -DomainName $domains -Ports 25 -FullResponse
    Test-DDDnsTtl -DomainName $domains
    Test-DDDnsZoneTransfer -DomainName $domains
    Test-DDDnsWildcard -DomainName $domains
    Test-DDEmailBimiRecord -DomainName $domains
    Test-DDEmailMtaSts -DomainName $domains
    Test-DDEmailProtocolTls -DomainName $domains
} -Verbose
