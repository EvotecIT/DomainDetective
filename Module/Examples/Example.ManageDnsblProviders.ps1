# Clear-Host

Import-Module $PSScriptRoot\..\DomainDetective.psd1 -Force


# Add a provider and capture the analysis object
$analysis = Add-DnsblProvider -Domain 'dnsbl.example.com' -Comment 'custom'
$analysis | Format-Table

# Remove the same provider by piping the analysis object
$analysis = $analysis | Remove-DnsblProvider -Domain 'dnsbl.example.com'
$analysis | Format-Table

# Clear the provider list on the same analysis object
$analysis = $analysis | Clear-DnsblProvider
$analysis | Format-Table

# Load providers from JSON into a fresh analysis object
$loaded = Import-DnsblConfig -Path $PSScriptRoot/../../DnsblProviders.sample.json -OverwriteExisting
$loaded | Format-Table
