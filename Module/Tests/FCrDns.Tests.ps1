Describe 'Test-DnsFcrDns cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DnsFcrDns -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-DnsFcrDns -DomainName '' } | Should -Throw
    }
}
