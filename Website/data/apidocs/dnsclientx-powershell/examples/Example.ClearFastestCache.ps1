# Clear the FastestWins fastest-endpoint cache
Clear-DnsMultiResolverCache

# Clear for specific providers
Clear-DnsMultiResolverCache -ResolverDnsProvider Cloudflare,Google

# Clear for specific endpoints
Clear-DnsMultiResolverCache -ResolverEndpoint '1.1.1.1:53','https://dns.google/dns-query'

