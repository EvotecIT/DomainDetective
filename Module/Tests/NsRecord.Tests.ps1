Describe 'Test-NsRecord cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-NsRecord -DomainName 'example.com'
        $result | Should -Not -BeNullOrEmpty
    }
}

