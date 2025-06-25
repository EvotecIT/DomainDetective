# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Gmail = Test-OpenRelay -HostName 'gmail-smtp-in.l.google.com' -Port 25 -Verbose
$Gmail | Format-Table

$Example = Test-OpenRelay -HostName 'mail.example.com' -Port 25 -Verbose
$Example | Format-Table

$Example = Test-OpenRelay -HostName 'mail.example.com'
$Example | Format-Table
