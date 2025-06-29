# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Report = Import-TlsRpt -Path './tlsrpt.json'
$Report | Format-Table
