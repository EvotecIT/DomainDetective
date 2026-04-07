Import-Module $PSScriptRoot\..\DnsClientX.psd1 -Force

Resolve-Dns -Pattern 'server[1-3].example.com' -DnsProvider Cloudflare | Format-Table
