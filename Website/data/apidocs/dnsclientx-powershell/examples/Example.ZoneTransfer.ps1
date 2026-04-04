Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

# Perform a zone transfer over TCP
Get-DnsZoneTransfer -Zone 'example.com' -Server '127.0.0.1' -Port 5353
