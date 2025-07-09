Describe 'Test-MailLatency cmdlet' {
    It 'exposes Port parameter' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $command = Get-Command Test-MailLatency
        $command.Parameters.Keys | Should -Contain 'Port'
        [DomainDetective.PowerShell.CmdletTestMailLatency]::new().Port | Should -Be 25
    }
}
