# SequentialAll tries endpoints in order until first success
Resolve-Dns -Name 'example.com' -Type A -DnsProvider Cloudflare, Google -ResolverStrategy SequentialAll | Format-Table

