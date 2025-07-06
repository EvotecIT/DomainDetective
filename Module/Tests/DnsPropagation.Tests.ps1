Describe 'Test-DnsPropagation cmdlet' {
    It 'accepts CountryCount parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Test-DnsPropagation -DomainName 'example.com' -RecordType A -CountryCount @{PL=0}
        $result | Should -BeNullOrEmpty
    }
}
