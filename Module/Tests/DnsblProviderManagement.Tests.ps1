Describe 'Add-DnsblProvider cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'test'
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if Domain is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Add-DnsblProvider -Domain '' } | Should -Throw
    }
}

Describe 'Remove-DnsblProvider cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $analysis = Add-DnsblProvider -Domain 'remove.example.com'
        $result = $analysis | Remove-DnsblProvider -Domain 'remove.example.com'
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if Domain is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Remove-DnsblProvider -Domain '' } | Should -Throw
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

Describe 'Import-DnsblConfig cmdlet' {
    It 'executes and returns analysis' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $path = "$PSScriptRoot/../../DnsblProviders.sample.json"
        $result = Import-DnsblConfig -Path $path -OverwriteExisting
        $result | Should -Not -BeNullOrEmpty
    }
    It 'throws if Path is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Import-DnsblConfig -Path '' } | Should -Throw
    }

    It 'skips duplicate domains' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $json = '{"providers":[{"domain":"dup.test"},{"domain":"DUP.test"}]}'
        $temp = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
        $path = Join-Path $temp ([guid]::NewGuid().ToString() + '.json')
        $json | Set-Content -Path $path
        try {
            $result = Import-DnsblConfig -Path $path -ClearExisting
            ($result.GetDNSBL() | Where-Object { $_.Domain -ieq 'dup.test' }).Count | Should -Be 1
        } finally {
            Remove-Item $path -ErrorAction SilentlyContinue
        }
    }
}
