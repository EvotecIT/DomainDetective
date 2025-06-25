# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Results = Test-SecurityTXT -DomainName 'google.com' -Verbose
$Results | Format-Table
$Results | Format-List

$Github = Test-SecurityTXT -DomainName 'github.com'
$Github | Format-Table

$Evotec = Test-SecurityTXT -DomainName 'evotec.pl'
$Evotec | Format-Table

