Clear-Host
Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

# Add a record
Invoke-DnsUpdate -Zone 'example.com' -Server '127.0.0.1' -Name 'www' -Type A -Data '192.0.2.1' -Ttl 300

# Delete a record
Invoke-DnsUpdate -Zone 'example.com' -Server '127.0.0.1' -Name 'www' -Type A -Delete
