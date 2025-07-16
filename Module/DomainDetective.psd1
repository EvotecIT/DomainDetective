@{
    AliasesToExport      = @('Add-DnsblProvider', 'Clear-DnsblProvider', 'Get-DomainSummary', 'Get-DomainFlattenedSpfIp', 'Get-RdapObject', 'Get-DomainWhois', 'Import-DmarcForensic', 'Import-DmarcReport', 'Import-DnsblConfig', 'Remove-DnsblProvider', 'Test-EmailArc', 'Test-EmailBimi', 'Test-DnsDomainBlacklist', 'Test-DnsCaa', 'Test-DomainContact', 'Test-TlsDane', 'Test-DnsDanglingCname', 'Test-EmailDkim', 'Test-EmailDmarc', 'Test-DnsBlacklist', 'Test-DnsPropagation', 'Test-DnsSec', 'Test-DnsTtl', 'Test-DnsTunneling', 'Test-DomainHealth', 'Test-DnsEdnsSupport', 'Test-DnsFcrDns', 'Test-NetworkIpNeighbor', 'Test-EmailLatency', 'Get-EmailHeaderInfo', 'Test-MxRecord', 'Test-DnsNs', 'Test-EmailOpenRelay', 'Test-NetworkPortAvailability', 'Test-Rdap', 'Test-Rpki', 'Test-DomainSecurityTxt', 'Test-DnsSmimea', 'Test-EmailSmtpTls', 'Test-DnsSoa', 'Test-EmailSpf', 'Test-EmailStartTls', 'Test-DomainThreatIntel', 'Test-EmailTlsRpt', 'Test-DomainCertificate', 'Test-DnsWildcard')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Add-DDDnsblProvider', 'Clear-DDDnsblProviderList', 'Get-CertificateInfo', 'Get-DDDomainHealthReport', 'Get-DDFlattenedSpfIp', 'Get-DDRdapObject', 'Get-DDDomainWhois', 'Import-DDDmarcForensic', 'Import-DDDmarcReport', 'Import-DDDnsblConfig', 'Import-TlsRpt', 'Invoke-DomainWizard', 'New-DmarcRecord', 'Remove-DDDnsblProvider', 'Start-DnsPropagationMonitor', 'Stop-DnsPropagationMonitor', 'Test-DDEmailArcRecord', 'Test-Autodiscover', 'Test-DDEmailBimiRecord', 'Test-DDDnsDomainBlacklist', 'Test-DDDnsCaaRecord', 'Test-DDDomainContactRecord', 'Test-DDTlsDaneRecord', 'Test-DDDnsDanglingCname', 'Test-Delegation', 'Test-DDEmailDkimRecord', 'Test-DmarcAggregate', 'Test-DDEmailDmarcRecord', 'Test-DDDnsBlacklistRecord', 'Test-DDDnsPropagation', 'Test-DDDnsSecStatus', 'Test-DDDnsTtl', 'Test-DDDnsTunneling', 'Test-DDDomainOverallHealth', 'Test-DDEdnsSupport', 'Test-DDDnsForwardReverse', 'Test-ImapTls', 'Test-DDIpNeighbor', 'Test-DDMailLatency', 'Get-DDEmailMessageHeaderInfo', 'Test-DDDnsMxRecord', 'Test-DDDnsNsRecord', 'Test-DDEmailOpenRelay', 'Test-Pop3Tls', 'Test-DDPortAvailability', 'Test-DDRdap', 'Test-ReverseDns', 'Test-DDRpki', 'Test-DDDomainSecurityTxt', 'Test-DDSmimeaRecord', 'Test-SmtpBanner', 'Test-DDEmailSmtpTls', 'Test-DDDnsSoaRecord', 'Test-DDEmailSpfRecord', 'Test-DDEmailStartTls', 'Test-DDThreatIntel', 'Test-DDEmailTlsRptRecord', 'Test-DDDomainCertificate', 'Test-DDDnsWildcard', 'Test-ZoneTransfer')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2025 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'DomainDetective is a PowerShell module that provides features to work with domains, DNS, and other related information.'
    FunctionsToExport    = @()
    GUID                 = 'a2986f0d-da11-43f5-a252-f9e1d1699776'
    ModuleVersion        = '0.2.0'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            ProjectUri = 'https://github.com/EvotecIT/DomainDetective'
            Tags       = @('Windows', 'MacOS', 'Linux')
        }
    }
    RootModule           = 'DomainDetective.psm1'
}