@{
    AliasesToExport      = @('Add-DnsblProvider', 'Clear-DnsblProvider', 'Get-DomainSummary', 'Get-DomainFlattenedSpfIp', 'Get-RdapObject', 'Get-SearchEngineInfo', 'Get-DomainWhois', 'Import-DmarcForensic', 'Import-DmarcReport', 'Import-DnsblConfig', 'Remove-DnsblProvider', 'Export-DomainReport', 'New-DomainReport', 'Generate-DomainReport', 'Test-EmailArc', 'Test-EmailAutoDiscover', 'Test-EmailBimi', 'Test-DnsDomainBlacklist', 'Test-DnsCaa', 'Test-DomainContact', 'Test-TlsDane', 'Test-DnsDanglingCname', 'Test-EmailDkim', 'Test-EmailDmarc', 'Test-DnsBlacklist', 'Test-DnsPropagation', 'Test-DnsSec', 'Test-DnsTtl', 'Test-DnsTunneling', 'Test-DomainHealth', 'Test-DnsEdnsSupport', 'Test-DnsFcrDns', 'Test-NetworkIpNeighbor', 'Test-EmailLatency', 'Get-EmailHeaderInfo', 'Test-MxRecord', 'Test-DnsNs', 'Test-EmailOpenRelay', 'Test-OpenResolver', 'Test-NetworkPortAvailability', 'Test-Rdap', 'Test-Rpki', 'Test-DomainSecurityTxt', 'Test-DnsSmimea', 'Test-EmailSmtpTls', 'Test-DnsSoa', 'Test-EmailSpf', 'Test-EmailStartTls', 'Test-DomainThreatIntel', 'Test-EmailTlsRpt', 'Test-DomainCertificate', 'Test-DnsWildcard', 'Get-CertificateInfo', 'Import-TlsRpt', 'Invoke-DomainWizard', 'New-DmarcRecord', 'Start-DnsPropagationMonitor', 'Stop-DnsPropagationMonitor', 'Test-Delegation', 'Test-DmarcAggregate', 'Test-ImapTls', 'Test-Pop3Tls', 'Test-ReverseDns', 'Test-SmtpBanner', 'Test-ZoneTransfer')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Add-DDDnsblProvider', 'Clear-DDDnsblProviderList', 'Get-DDCertificateInfo', 'Get-DDDomainHealthReport', 'Get-DDFlattenedSpfIp', 'Get-DDRdapObject', 'Get-DDSearchEngineInfo', 'Get-DDDomainWhois', 'Import-DDDmarcForensic', 'Import-DDDmarcReport', 'Import-DDDnsblConfig', 'Import-DDTlsRpt', 'Invoke-DDDomainWizard', 'New-DDDmarcRecord', 'Remove-DDDnsblProvider', 'Show-DDDomainReport', 'Start-DDDnsPropagationMonitor', 'Stop-DDDnsPropagationMonitor', 'Test-DDEmailArcRecord', 'Test-DDEmailAutoDiscover', 'Test-DDEmailBimiRecord', 'Test-DDDnsDomainBlacklist', 'Test-DDDnsCaaRecord', 'Test-DDDomainContactRecord', 'Test-DDTlsDaneRecord', 'Test-DDDnsDanglingCname', 'Test-DDDelegation', 'Test-DDEmailDkimRecord', 'Test-DDDmarcAggregate', 'Test-DDEmailDmarcRecord', 'Test-DDDnsBlacklistRecord', 'Test-DDDnsPropagation', 'Test-DDDnsSecStatus', 'Test-DDDnsTtl', 'Test-DDDnsTunneling', 'Test-DDDomainOverallHealth', 'Test-DDEdnsSupport', 'Test-DDDnsForwardReverse', 'Test-DDImapTls', 'Test-DDIpNeighbor', 'Test-DDMailLatency', 'Get-DDEmailMessageHeaderInfo', 'Test-DDDnsMxRecord', 'Test-DDDnsNsRecord', 'Test-DDEmailOpenRelay', 'Test-DDDnsOpenResolver', 'Test-DDPop3Tls', 'Test-DDPortAvailability', 'Test-DDRdap', 'Test-DDReverseDns', 'Test-DDRpki', 'Test-DDDomainSecurityTxt', 'Test-DDSmimeaRecord', 'Test-DDSmtpBanner', 'Test-DDEmailSmtpTls', 'Test-DDDnsSoaRecord', 'Test-DDEmailSpfRecord', 'Test-DDEmailStartTls', 'Test-DDThreatIntel', 'Test-DDEmailTlsRptRecord', 'Test-DDDomainCertificate', 'Test-DDDnsWildcard', 'Test-DDZoneTransfer')
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