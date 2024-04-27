Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DaneRecord -DomainName 'evotec.pl' -Verbose
$Results | Format-Table

$Results = Test-DaneRecord -DomainName 'ietf.org' -Verbose
$Results | Format-Table

