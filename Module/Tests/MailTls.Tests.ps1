Describe 'Test-DDEmailProtocolTls cmdlet' {
    It 'returns MailTlsInfo view' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DDEmailProtocolTls -DomainName 'example.com' -Protocol Smtp -ErrorAction SilentlyContinue
        $result | Should -BeOfType 'DomainDetective.Views.MailTlsInfo'
    }
}
