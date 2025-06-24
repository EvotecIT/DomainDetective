# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Mx = Test-MxRecord -DomainName 'evotec.pl' -Verbose
$Mx | Format-Table

$Google = Test-MxRecord -DomainName 'google.com'
$Google | Format-Table
