@{
    AliasesToExport      = @('Get-DnsZoneTransfer', 'Resolve-DnsQuery')
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @('Clear-DnsMultiResolverCache', 'Get-DnsService', 'Invoke-DnsUpdate', 'Get-DnsZone', 'Find-DnsService', 'Resolve-Dns')
    CompanyName          = 'Evotec'
    CompatiblePSEditions = @('Desktop', 'Core')
    Copyright            = '(c) 2011 - 2025 Przemyslaw Klys @ Evotec. All rights reserved.'
    Description          = 'DnsClientX is PowerShell module that allows you to query DNS servers for information. It supports DNS over UDP, TCP and DNS over HTTPS (DoH) and DNS over TLS (DoT). It supports multiple types of DNS queries and can be used to query public DNS servers, private DNS servers and has built-in DNS Providers.'
    FunctionsToExport    = @()
    GUID                 = '77fa806c-70b7-48d9-8b88-942ed73f24ed'
    HelpInfoURI          = 'https://github.com/EvotecIT/DnsClientX/blob/master/README.md'
    ModuleVersion        = '1.0.7'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            IconUri    = 'https://raw.githubusercontent.com/EvotecIT/DnsClientX/master/Assets/Icons/DnsClientX3_128x128.png'
            ProjectUri = 'https://github.com/EvotecIT/DnsClientX'
            Tags       = @('Windows', 'MacOS', 'Linux')
        }
    }
    RootModule           = 'DnsClientX.psm1'
}
