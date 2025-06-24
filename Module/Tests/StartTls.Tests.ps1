Describe 'Test-StartTls cmdlet' {
    It 'executes and returns analysis on default port' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-StartTls -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result | Should -Not -BeNullOrEmpty
    }
    It 'accepts custom port parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-StartTls -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat -Port 587
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-StartTls -DomainName '' } | Should -Throw
    }
}
