Describe 'Test-NsRecord cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-NsRecord -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result | Should -Not -BeNullOrEmpty
    }
}

