# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-SpfRecord -DomainName 'google.com' -Verbose
$Results | Format-Table

$ResultsMicrosoft = Test-SpfRecord -DomainName 'microsoft.com' -Verbose
$ResultsMicrosoft | Format-Table
$ResultsMicrosoft | Format-List

$ResultsEvotec = Test-SpfRecord -DomainName 'evotec.pl' -Verbose
$ResultsEvotec | Format-Table
$ResultsEvotec | Format-List

$ResultsIdn = Test-SpfRecord -DomainName 'xn--bcher-kva.ch' -Verbose
$ResultsIdn | Format-Table
$ResultsIdn | Format-List
