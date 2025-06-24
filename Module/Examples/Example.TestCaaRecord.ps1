# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-CaaRecord -DomainName 'evotec.pl'
$Results | Format-Table

$Google = Test-CaaRecord -DomainName 'google.com'
$Google | Format-Table

$VerboseExample = Test-CaaRecord -DomainName 'example.com' -Verbose
$VerboseExample | Format-Table
