# RoundRobin distributes queries to balance load; cap total and per-endpoint concurrency
$names = 1..12 | ForEach-Object { "host$_.example" }
Resolve-Dns -Name $names -Type A -DnsProvider System, Cloudflare, Quad9 -ResolverStrategy RoundRobin -MaxParallelism 16 -PerEndpointMaxInFlight 4 | Format-Table
