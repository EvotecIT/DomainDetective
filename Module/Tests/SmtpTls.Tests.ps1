Describe 'Test-EmailSmtpTls cmdlet' {
    It 'returns SMTPTLSAnalysis object' {
        Import-Module "$PSScriptRoot/../DomainDetective.psd1" -Force
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $listener.Stop()
        $result = Test-EmailSmtpTls -HostName 'localhost' -Port $port -ErrorAction SilentlyContinue
        $result | Should -BeOfType 'DomainDetective.SMTPTLSAnalysis'
    }
}
