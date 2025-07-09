# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Result = Test-MailLatency -HostName 'mail.example.com' -Port 25 -Verbose
$Result | Format-Table
