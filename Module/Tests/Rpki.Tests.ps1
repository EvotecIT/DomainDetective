Describe 'Test-Rpki cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-Rpki -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-Rpki -DomainName '' } | Should -Throw
    }
}
