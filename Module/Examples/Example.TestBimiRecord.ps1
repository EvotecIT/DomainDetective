# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-BimiRecord -DomainName 'evotec.pl' -Verbose
$Results | Format-Table

$Example = Test-BimiRecord -DomainName 'example.com'
$Example | Format-Table
