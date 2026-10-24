---
title: Multi-resolver and benchmarking
description: Query several DNS resolvers with DnsClientX strategies, cap concurrency, cache answers, and probe, benchmark and score resolvers for the network you are on.
slug: multi-resolver
collection: docs
layout: docs
---

`DnsMultiResolver` sends one question to several endpoints and decides which answer to return. The PowerShell module exposes the same behaviour through `Resolve-Dns -ResolverStrategy`.

## Strategies

| Strategy | Behaviour |
| --- | --- |
| `FirstSuccess` | Races a bounded set of endpoints and returns the first success; the others are cancelled. |
| `FastestWins` | Warms the endpoints, prefers the fastest successful one and caches that choice for a while. |
| `SequentialFallback` | Tries endpoints in order and returns the first terminal answer or the best transport error. |
| `RoundRobin` | Spreads queries across endpoints to balance load, with fallback on failure. |

```csharp
using DnsClientX;

var endpoints = EndpointParser.TryParseMany(new[] {
    "1.1.1.1:53",
    "8.8.8.8:53",
    "https://dns.google/dns-query"
}, out var errors);

var options = new MultiResolverOptions {
    Strategy = MultiResolverStrategy.FirstSuccess,
    MaxParallelism = 4,
    RespectEndpointTimeout = true
};

using var resolver = new DnsMultiResolver(endpoints, options);
var response = await resolver.QueryAsync("evotec.pl", DnsRecordType.A);
Console.WriteLine($"{response.RoundTripTime.TotalMilliseconds} ms via {response.UsedTransport} @ {response.UsedEndpoint}");

// Order-preserving batch with isolated failures
var results = await resolver.QueryBatchAsync(new[] { "a.com", "b.com", "c.com" }, DnsRecordType.A);

// One response per endpoint, for consensus and diagnostics
var all = await resolver.QueryAllAsync("evotec.pl", DnsRecordType.DNSKEY);
```

`MaxParallelism` caps all in-flight queries and `PerEndpointMaxInFlight` caps each endpoint. Answers carry `TtlMin` and `TtlAvg`, and terminal NXDOMAIN or NODATA responses are returned as answers rather than treated as transport failures.

## From PowerShell

```powershell
# Balance across providers with caps
Resolve-Dns -Name @('a.com','b.com') -Type A `
  -DnsProvider System,Cloudflare,Quad9 `
  -ResolverStrategy RoundRobin -MaxParallelism 32 -PerEndpointMaxInFlight 4

# EDNS client subnet and DNSSEC details
Resolve-Dns -Name evotec.pl -Type A `
  -ResolverEndpoint 'https://dns.google/dns-query' `
  -EnableEdns -ClientSubnet '192.0.2.0/24' -RequestDnsSec -ValidateDnsSec -FullResponse

# Reset the FastestWins choice
Clear-DnsMultiResolverCache
```

## Probe, benchmark and select

Resolver quality depends on the network you are on. DnsClientX can validate a catalog of resolvers, probe them, benchmark them, save the scores and choose an endpoint from that evidence later.

```powershell
Test-DnsResolverCatalog -ResolverEndpointFile .\resolvers.txt
Test-DnsProbe -ResolverEndpointFile .\resolvers.txt
Test-DnsBenchmark -Name evotec.pl -DnsProvider Cloudflare,Google,Quad9
Get-DnsResolverSelection
```

Saved snapshots keep a schema version, explicit endpoint settings and runtime capability hints, so a recommendation from one machine is not silently reused where its transport is unavailable.

## Results can legitimately differ

Resolvers can return different answers at the same moment because of CDN geolocation, cache state, EDNS client subnet, filtering policy or propagation. Compare RRsets with that in mind rather than expecting identical answers from every provider.

## Next steps

- [Transports and endpoints](/docs/dnsclientx/transports/)
- [DnsClientX PowerShell guide](/docs/dnsclientx/powershell/)
