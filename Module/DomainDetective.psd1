@{
    AliasesToExport      = @()
    Author               = 'Przemyslaw Klys'
    CmdletsToExport      = @(
        'Test-DomainBlacklist',
        'Test-DaneRecord',
        'Test-DkimRecord',
        'Test-SpfRecord',
        'Test-NsRecord',
        'Test-DnsPropagation',
        'Test-CaaRecord',
        'Test-SecurityTXT',
        'Test-StartTls',
        'Test-DomainHealth',
        'Add-DnsblProvider',
        'Remove-DnsblProvider',
        'Clear-DnsblProvider',
        'Load-DnsblConfig'
    )
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