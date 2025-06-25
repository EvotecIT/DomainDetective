# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$DnsSec = Test-DnsSec -DomainName 'evotec.pl' -Verbose
$DnsSec | Format-Table
$DnsSec | Format-List

$Example = Test-DnsSec -DomainName 'example.com'
$Example | Format-List
