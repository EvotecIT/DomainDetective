# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Mx = Test-MxRecord -DomainName 'evotec.pl' -Verbose
$Mx | Format-Table
$Mx | Format-List

$Google = Test-MxRecord -DomainName 'google.com'
$Google | Format-Table
$Google | Format-List
