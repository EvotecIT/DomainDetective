Describe 'Test-Rpki cmdlet' {
    It 'executes without error' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-Rpki -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat } | Should -Not -Throw
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-Rpki -DomainName '' } | Should -Throw
    }
}
