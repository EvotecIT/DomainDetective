Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport -Compose {
#     Test-DDEmailSpfRecord -DomainName 'contoso.com'
#     Test-DDDnsBlacklist -NameOrIpAddress '203.0.113.5'
#     Test-DDMailDomainClassification -DomainName 'contoso.com'
# }


# Test-DDDomainOverallHealth -DomainName 'evotec.pl' -HealthCheckType SPF, DKIM, DMARC, MTASTS, TLSRPT -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport

Export-DDSecurityReport -Scope Detailed -ExportFormat Word -ExportPath "$PSScriptRoot\Reports" -OpenReport -Compose {
    Test-DDEmailSpfRecord -DomainName 'evotec.pl', 'evotec.xyz'
    Test-DDEmailDkimRecord -DomainName 'evotec.pl', 'evotec.xyz'
    Test-DDEmailDmarcRecord -DomainName 'evotec.pl', 'evotec.xyz'
    #Test-DDEmailTlsRptRecord -DomainName 'evotec.pl', 'evotec.xyz'
    #Test-DDMailDomainClassification -DomainName 'evotec.pl', 'evotec.xyz'
}
