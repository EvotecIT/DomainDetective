Describe 'Test-EmailStartTls cmdlet' {
    It 'exposes Port parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $command = Get-Command Test-EmailStartTls
        $command.Parameters.Keys | Should -Contain 'Port'
        [DomainDetective.PowerShell.CmdletTestStartTls]::new().Port | Should -Be 25
    }
    It 'throws if DomainName is empty' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        { Test-EmailStartTls -DomainName '' } | Should -Throw
    }
}
