# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$TlsRpt = Test-TlsRptRecord -DomainName 'evotec.pl' -Verbose
$TlsRpt | Format-Table

$Example = Test-TlsRptRecord -DomainName 'example.com'
$Example | Format-Table
