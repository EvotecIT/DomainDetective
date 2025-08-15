# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Report = Import-DDTlsRpt -Path './tlsrpt.json'
$Report | Format-Table
