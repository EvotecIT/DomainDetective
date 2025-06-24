# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Dmarc = Test-DmarcRecord -DomainName 'evotec.pl' -Verbose
$Dmarc | Format-Table
$Dmarc | Format-List

$Example = Test-DmarcRecord -DomainName 'example.com'
$Example | Format-Table
$Example | Format-List