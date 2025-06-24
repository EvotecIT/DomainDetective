# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-DaneRecord -DomainName 'evotec.pl' -Verbose
$Results | Format-List

$Results = Test-DaneRecord -DomainName 'ietf.org' -Verbose
$Results | Format-List

