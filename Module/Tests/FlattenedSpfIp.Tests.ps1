Describe 'Get-FlattenedSpfIp cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Get-FlattenedSpfIp -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Get-FlattenedSpfIp -DomainName '' } | Should -Throw
    }
}
