# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Gmail = Test-SmtpTls -HostName 'gmail.com' -Port 25 -Verbose
$Gmail | Format-Table

$Example = Test-SmtpTls -HostName 'mail.example.com' -ShowChain -Verbose
$Example | Format-List
