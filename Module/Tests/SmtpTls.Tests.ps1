Describe 'Test-DDEmailSmtpTls cmdlet' {
    It 'returns MailTlsInfo view' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        $result = Test-DDEmailSmtpTls -HostName 'localhost' -Port $port -ErrorAction SilentlyContinue
        $result | Should -BeOfType 'DomainDetective.Views.MailTlsInfo'
    }
}
