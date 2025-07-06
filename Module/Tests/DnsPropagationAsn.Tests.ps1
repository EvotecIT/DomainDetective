Describe 'Test-DnsPropagation ASN filters' {
    It 'runs with Asn parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Test-DnsPropagation -DomainName 'example.com' -RecordType A -Take 0 -Asn '396982' | Should -BeNullOrEmpty
    }
    It 'runs with AsnName parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Test-DnsPropagation -DomainName 'example.com' -RecordType A -Take 0 -AsnName 'GOOGLE' | Should -BeNullOrEmpty
    }
}
