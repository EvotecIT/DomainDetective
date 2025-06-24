# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-NsRecord -DomainName 'google.com' -Verbose
$Results | Format-Table

$Cloudflare = Test-NsRecord -DomainName 'example.com' -DnsEndpoint Cloudflare
$Cloudflare | Format-Table

$Evotec = Test-NsRecord -DomainName 'evotec.pl' -Verbose
$Evotec | Format-Table
