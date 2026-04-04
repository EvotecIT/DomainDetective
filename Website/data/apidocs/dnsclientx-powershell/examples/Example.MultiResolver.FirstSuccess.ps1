# FirstSuccess across multiple providers (auto multi-resolver when more than one -DnsProvider is given)
$names = @('example.com', 'cloudflare.com', 'google.com')
Resolve-Dns -Name $names -Type A -DnsProvider Cloudflare, Google -ResolverStrategy FirstSuccess -MaxParallelism 8 | Format-Table

