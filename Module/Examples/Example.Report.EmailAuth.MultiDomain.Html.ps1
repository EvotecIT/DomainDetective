Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Multi-domain HTML dashboard showcasing most report sections end-to-end.
# Note: Results vary over time as DNS and provider configurations change.
$domains = @('evotec.pl', 'evotec.xyz', 'cyberdrain.com')
$dkimSelectors = @('s1', 's2')
$reportPath = Join-Path -Path $PSScriptRoot -ChildPath 'Reports'

Export-DDSecurityReport -ExportFormat Html -ExportPath $reportPath -Scope Detailed -DomainOrder Input -SectionOrderMode Custom `
    -SectionOrder MX,SPF,DKIM,DMARC,BIMI,MTA-STS,TLS-RPT,DNSBL,DNSSEC,DANE,RPKI,NS,SOA,CAA,TTL,ZoneTransfer,Wildcard,Classification,MAILTLS `
    -OpenInBrowser -Compose {
    Test-DDEmailSpfRecord -DomainName $domains
    Test-DDEmailDkimRecord -DomainName $domains -Selectors $dkimSelectors -FullResponse
    Test-DDEmailDmarcRecord -DomainName $domains
    Test-DDEmailTlsRptRecord -DomainName $domains

    Test-DDDnsBlacklist -NameOrIpAddress $domains -TreatAsDomain -FullResponse
    Test-DDRpki -DomainName $domains
    Test-DDMailDomainClassification -DomainName $domains

    foreach ($domain in $domains) {
        Test-DDDnsMxRecord -DomainName $domain
        Test-DDDnsNsRecord -DomainName $domain
        Test-DDDnsSoaRecord -DomainName $domain
        Test-DDDnsCaaRecord -DomainName $domain
        Test-DDDnsSecStatus -DomainName $domain
        Test-DDTlsDaneRecord -DomainName $domain -Ports 25 -FullResponse
        Test-DDDnsTtl -DomainName $domain
        Test-DDDnsZoneTransfer -DomainName $domain
        Test-DDDnsWildcard -DomainName $domain
        Test-DDEmailBimiRecord -DomainName $domain

        try {
            Test-DDEmailMtaSts -DomainName $domain
            Test-DDEmailMxTls -DomainName $domain
        } catch {
            Write-Warning -Message "Mail TLS/MTA-STS checks failed for ${domain}: $($_.Exception.Message)"
        }
    }
}
