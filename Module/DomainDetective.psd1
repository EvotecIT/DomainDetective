@{
    AliasesToExport      = @(
        'Add-DnsblProvider',
        'Clear-DnsblProvider',
        'Get-DomainSummary',
        'Get-DomainWhois',
        'Get-DomainFlattenedSpfIp',
        'Import-DnsblConfig',
        'Import-DmarcReport',
        'Remove-DnsblProvider',
        'Test-EmailArc',
        'Test-EmailBimi',
        'Test-EmailDkim',
        'Test-EmailDmarc',
        'Test-EmailSpf',
        'Test-EmailTlsRpt',
        'Test-EmailStartTls',
        'Test-EmailSmtpTls',
        'Test-EmailOpenRelay',
        'Get-EmailHeaderInfo',
        'Test-EmailLatency',
        'Test-DnsCaa',
        'Test-DnsNs',
        'Test-DnsSoa',
        'Test-DnsSec',
        'Test-DnsBlacklist',
        'Test-DnsDomainBlacklist',
        'Test-DnsDanglingCname',
        'Test-DnsPropagation',
        'Test-DnsTtl',
        'Test-DnsTunneling',
        'Test-DnsWildcard',
        'Test-DnsEdnsSupport',
        'Test-DnsSmimea',
        'Test-DnsFcrDns',
        'Test-MxRecord',
        'Test-DomainContact',
        'Test-DomainSecurityTxt',
        'Test-DomainCertificate',
        'Test-DomainHealth',
        'Test-DomainThreatIntel',
        'Test-TlsDane',
        'Test-NetworkIpNeighbor',
        'Test-NetworkPortAvailability'
    )
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Add-DDDnsblProvider', 'Clear-DDDnsblProviderList', 'Get-DDDomainHealthReport', 'Get-DDDomainWhois', 'Get-DDFlattenedSpfIp', 'Import-DDDnsblConfig', 'Import-DDDmarcReport', 'Remove-DDDnsblProvider', 'Test-DDEmailArcRecord', 'Test-DDEmailBimiRecord', 'Test-DDDnsDomainBlacklist', 'Test-DDDnsCaaRecord', 'Test-DDDomainContactRecord', 'Test-DDTlsDaneRecord', 'Test-DDSmimeaRecord', 'Test-DDEmailDkimRecord', 'Test-DDEmailDmarcRecord', 'Test-DDDnsBlacklistRecord', 'Test-DDDnsPropagation', 'Test-DDDnsSecStatus', 'Test-DDDomainOverallHealth', 'Test-DDDnsMxRecord', 'Test-DDDnsNsRecord', 'Test-DDEmailOpenRelay', 'Get-DDEmailMessageHeaderInfo', 'Test-DDDomainSecurityTxt', 'Test-DDEmailSmtpTls', 'Test-DDMailLatency', 'Test-DDDnsSoaRecord', 'Test-DDEmailSpfRecord', 'Test-DDEmailStartTls', 'Test-DDEmailTlsRptRecord', 'Test-DDDomainCertificate', 'Test-DDDnsDanglingCname', 'Test-DDDnsForwardReverse', 'Test-DDThreatIntel', 'Test-DDDnsTtl', 'Test-DDDnsTunneling', 'Test-DDIpNeighbor', 'Test-DDPortAvailability', 'Test-DDDnsWildcard', 'Test-DDEdnsSupport')
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
    RootModule           = 'DomainDetective.psm1'}