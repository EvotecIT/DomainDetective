# FastestWins warms endpoints and caches fastest for a short duration
Resolve-Dns -Name 'example.com' -Type A -DnsProvider Cloudflare,Google -ResolverStrategy FastestWins -FastestCacheMinutes 10 | Format-Table

# Second call should prefer the cached fastest endpoint
Resolve-Dns -Name 'cloudflare.com' -Type A -DnsProvider Cloudflare,Google -ResolverStrategy FastestWins -FastestCacheMinutes 10 | Format-Table

