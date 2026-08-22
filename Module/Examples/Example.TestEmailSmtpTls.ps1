# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Per-host TLS details (leaf certificate + cipher/protocol)
$GmailTls = Test-EmailSmtpTls -HostName 'gmail-smtp-in.l.google.com' -Port 25 -Verbose -ErrorAction SilentlyContinue
$GmailTls | Select-Object Protocol,Tls13Used,CipherSuite,CipherAlgorithm,CipherStrength,
    CertificateSubject,CertificateIssuer,CertificateNotAfter | Format-List

# Show full chain for a host
$Example = Test-EmailSmtpTls -HostName 'mail.example.com' -ShowChain -Verbose -ErrorAction SilentlyContinue
$Example | Format-List

# Pin a backend address while preserving mail.example.com for SNI and certificate validation
$Pinned = Test-DDEmailSmtpTls -HostName 'mail.example.com' -Port 587 `
    -ConnectAddress '192.0.2.10' -AddressFamily IPv4
$Pinned.Servers | Select-Object HostName,ConnectAddress,RemoteAddress,HostnameMatch,Grade | Format-Table
