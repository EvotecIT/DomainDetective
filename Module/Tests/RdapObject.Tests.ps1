Describe 'Get-RdapObject cmdlet' {
    It 'retrieves domain data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Get-RdapObject -Domain 'example.com'
        $result | Should -Not -BeNullOrEmpty
    }
    It 'retrieves IP data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Get-RdapObject -Ip '192.0.2.1'
        $result | Should -Not -BeNullOrEmpty
    }
}

