Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Custom composition: SPF for domain + DNSBL for a specific IP address
$spf = Test-DDEmailSpfRecord -DomainName 'contoso.com'
$dnsbl = Test-DDDnsBlacklist -NameOrIpAddress '203.0.113.5'

($spf + $dnsbl) | Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport



Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport {
    Test-DDEmailSpfRecord -DomainName 'contoso.com'
    Test-DDDnsBlacklist -NameOrIpAddress '203.0.113.5'
}