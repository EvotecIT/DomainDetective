# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Gmail = Test-StartTls -DomainName 'gmail.com' -Verbose
$Gmail | Format-Table

$Evotec = Test-StartTls -DomainName 'evotec.pl' -Port 25
$Evotec | Format-Table

$Example = Test-StartTls -DomainName 'example.com' -DnsEndpoint Cloudflare -Port 587
$Example | Format-Table

# Test a single host on a custom port
$HostTls = Test-StartTls -DomainName 'example.com' -Port 2525
$HostTls | Format-Table
