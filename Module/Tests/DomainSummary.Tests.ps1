Describe 'Get-DomainSummary cmdlet' {
    It 'returns a summary containing a numeric score' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Get-DomainSummary -DomainName 'example.com' -DnsEndpoint CloudflareWireFormat
        $result.Score | Should -BeOfType 'System.Int32'
    }
}
