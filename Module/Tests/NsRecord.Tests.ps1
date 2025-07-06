Describe 'Test-NsRecord cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-NsRecord -DomainName 'example.com'
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-NsRecord -DomainName '' } | Should -Throw
    }
}

