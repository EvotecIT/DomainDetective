﻿@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Add-DnsblProvider', 'Clear-DnsblProvider', 'Get-DomainSummary', 'Get-WhoisInfo', 'Import-DnsblConfig', 'Import-DmarcReport', 'Remove-DnsblProvider', 'Test-Arc', 'Test-BimiRecord', 'Test-DomainBlacklist', 'Test-CaaRecord', 'Test-ContactRecord', 'Test-DaneRecord', 'Test-SmimeaRecord', 'Test-DkimRecord', 'Test-DmarcRecord', 'Test-DNSBLRecord', 'Test-DnsPropagation', 'Test-DnsSec', 'Test-DomainHealth', 'Test-MxRecord', 'Test-NsRecord', 'Test-OpenRelay', 'Test-MessageHeader', 'Test-SecurityTXT', 'Test-SmtpTls', 'Test-SoaRecord', 'Test-SpfRecord', 'Test-StartTls', 'Test-TlsRptRecord', 'Test-WebsiteCertificate', 'Test-DanglingCname', 'Test-FCrDns', 'Test-ThreatIntel', 'Test-DnsTtl', 'Test-DnsTunneling', 'Test-IpNeighbor', 'Test-PortAvailability', 'Test-WildcardDns', 'Test-EdnsSupport')
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