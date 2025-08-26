# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

# Capture SMTP banner details (greeting code, server domain, response time)
$Banner = Test-SmtpBanner -HostName 'gmail-smtp-in.l.google.com' -Port 25 -Verbose
$Banner | Format-List Host,Port,GreetingCode,ServerDomain,StartsWith220,ValidFormat,ResponseTimeMs,Banner

# Validate expected hostname/software strings
$BannerCheck = Test-SmtpBanner -HostName 'gmail-smtp-in.l.google.com' -Port 25 -ExpectedHostname 'google' -ExpectedSoftware 'ESMTP'
$BannerCheck | Select-Object Host,Port,HostnameMatch,SoftwareMatch,Banner | Format-List

