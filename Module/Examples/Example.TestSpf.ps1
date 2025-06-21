# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-SpfRecord -DomainName 'google.com' -Verbose
$Results | Format-Table

$ResultsMicrosoft = Test-SpfRecord -DomainName 'microsoft.com' -Verbose
$ResultsMicrosoft | Format-Table

$ResultsEvotec = Test-SpfRecord -DomainName 'evotec.pl' -Verbose
$ResultsEvotec | Format-Table
$ResultsEvotec | Format-List