# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# STARTTLS typed details per MX host (banner, EHLO lines, capabilities, TLS)
$Gmail = Test-EmailStartTls -DomainName 'gmail.com' -Verbose
$Gmail | Select-Object Host,Port,StartTlsAdvertised,TlsNegotiated,TlsProtocol,
    @{N='Capabilities';E={$_.Capabilities -join ' '}} | Format-Table -AutoSize

# Show certificate summary and ALPN when available
$Evotec = Test-EmailStartTls -DomainName 'evotec.pl' -Port 25
$Evotec | Select-Object Host,CertificateSubject,CertificateIssuer,CertificateNotAfter,AlpnProtocol | Format-Table -AutoSize

# Get the full analysis container for scripting
$Example = Test-EmailStartTls -DomainName 'example.com' -DnsEndpoint System -Port 587 -FullResponse
$Example.ServerDetails.Values | Select-Object Host,Port,StartTlsAdvertised,TlsNegotiated | Format-Table

# Test STARTTLS advertisement on one backend and retain the logical host in the evidence
$Pinned = Test-DDEmailStartTls -HostName 'mail.example.com' -Port 587 `
    -ConnectAddress '192.0.2.10' -AddressFamily IPv4
$Pinned.Servers | Select-Object HostName,ConnectAddress,RemoteAddress,StartTlsAdvertised,TlsNegotiated | Format-Table
