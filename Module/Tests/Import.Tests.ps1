Describe 'DomainDetective module' {
    It 'imports successfully' {
        { Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force } | Should -Not -Throw
    }

    It 'exposes Test-SpfRecord cmdlet' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Get-Command Test-SpfRecord -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'exposes Add-DnsblProvider cmdlet' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Get-Command Add-DnsblProvider -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }
}
