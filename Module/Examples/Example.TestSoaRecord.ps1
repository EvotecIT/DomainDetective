# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Soa = Test-SoaRecord -DomainName 'evotec.pl' -Verbose
$Soa | Format-Table

$Example = Test-SoaRecord -DomainName 'example.com'
$Example | Format-Table
