Describe 'Get-FlattenedSpfIp cmdlet' {
    It 'executes and returns data' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $result = Get-FlattenedSpfIp -DomainName 'example.com' -TestSpfRecord 'v=spf1 ip4:192.0.2.10 -all'
        $result | Should -Not -BeNullOrEmpty
        $result | Should -Contain '192.0.2.10'
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Get-FlattenedSpfIp -DomainName '' } | Should -Throw
    }
}
