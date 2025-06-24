# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Gmail = Test-StartTls -DomainName 'gmail.com' -Verbose
$Gmail | Format-Table

$Evotec = Test-StartTls -DomainName 'evotec.pl' -Port 25
$Evotec | Format-Table

$Example = Test-StartTls -DomainName 'example.com' -DnsEndpoint Cloudflare
$Example | Format-Table
