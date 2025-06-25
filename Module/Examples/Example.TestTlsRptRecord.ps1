# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$TlsRpt = Test-TlsRptRecord -DomainName 'evotec.pl' -Verbose
$TlsRpt | Format-Table
$TlsRpt | Format-List

$Example = Test-TlsRptRecord -DomainName 'example.com'
$Example | Format-Table
$Example | Format-List
