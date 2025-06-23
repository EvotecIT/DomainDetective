Describe 'Add-DnsblProvider cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'test'
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'Remove-DnsblProvider cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $analysis = Add-DnsblProvider -Domain 'remove.example.com'
        $result = $analysis | Remove-DnsblProvider -Domain 'remove.example.com'
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'Clear-DnsblProvider cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        Add-DnsblProvider -Domain 'clear.example.com' | Out-Null
        $result = Clear-DnsblProvider
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'Load-DnsblConfig cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $path = "$PSScriptRoot/../../DnsblProviders.sample.json"
        $result = Load-DnsblConfig -Path $path -OverwriteExisting
        $result | Should -Not -BeNullOrEmpty
    }
}
