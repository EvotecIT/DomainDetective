# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force

$Added = Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'custom'
$Added | Format-Table

$Removed = Remove-DnsblProvider -Domain 'dnsbl.example.com'
$Removed | Format-Table

$Cleared = Clear-DnsblProvider
$Cleared | Format-Table

$Loaded = Import-DnsblConfig -Path $PSScriptRoot/../../DnsblProviders.sample.json -OverwriteExisting
$Loaded | Format-Table
