# Endpoint string formats supported by -ResolverEndpoint
# IPv4 with port, IPv6 with brackets, hostname with port, and DoH URL
$endpoints = @(
    '1.1.1.1:53',
    '[2606:4700:4700::1111]:53',
    'dns.google:53',
    'https://dns.google/dns-query'
)
Resolve-Dns -Name 'example.com' -Type A -ResolverEndpoint $endpoints -ResolverStrategy FirstSuccess | Format-Table

