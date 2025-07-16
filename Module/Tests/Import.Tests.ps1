Describe 'DomainDetective module' {
    It 'imports successfully' {
        { Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force } | Should -Not -Throw
    }

    It 'exposes Test-EmailSpf cmdlet' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Get-Command Test-EmailSpf -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'exposes Add-DnsblProvider cmdlet' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Get-Command Add-DnsblProvider -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }

    It 'exposes Import-DmarcForensic cmdlet' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Get-Command Import-DmarcForensic -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }
}
