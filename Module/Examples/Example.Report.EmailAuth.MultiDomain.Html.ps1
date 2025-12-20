Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$domains = @('evotec.pl', 'evotec.xyz')

$healthCheckTypes = @(
    'MX',
    'SPF',
    'DKIM',
    'DMARC',
    'ARC',
    'BIMI',
    'MTASTS',
    'TLSRPT',
    'DNSBL',
    'DNSSEC',
    'DANE',
    'RPKI',
    'NS',
    'SOA',
    'CAA',
    'TTL',
    'ZONETRANSFER',
    'WILDCARDDNS',
    'MAILCLASSIFICATION'
)

Test-DDDomainOverallHealth -DomainName $domains -HealthCheckType $healthCheckTypes -DkimSelectors @('s1', 's2') -ExportFormat Html -ExportPath "$PSScriptRoot\Reports" -OpenInBrowser
