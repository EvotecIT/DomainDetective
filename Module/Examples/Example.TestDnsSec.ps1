# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DnsSec = Test-DnsSec -DomainName 'evotec.pl' -Verbose
$DnsSec | Format-Table

$Example = Test-DnsSec -DomainName 'example.com'
$Example | Format-Table
