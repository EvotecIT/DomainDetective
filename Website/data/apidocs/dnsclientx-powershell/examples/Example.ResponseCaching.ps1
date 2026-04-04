# Enable TTL-based response caching for repeated lookups
Resolve-Dns -Name 'example.com' -Type A -DnsProvider Cloudflare,Google -ResolverStrategy FirstSuccess -ResponseCache -CacheExpirationSeconds 30 -MinCacheTtlSeconds 1 -MaxCacheTtlSeconds 3600 | Format-Table

# Repeat the same query to benefit from cache
Resolve-Dns -Name 'example.com' -Type A -DnsProvider Cloudflare,Google -ResolverStrategy FirstSuccess -ResponseCache -CacheExpirationSeconds 30 -MinCacheTtlSeconds 1 -MaxCacheTtlSeconds 3600 | Format-Table

