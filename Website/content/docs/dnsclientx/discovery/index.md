---
title: Service discovery
description: Discover services with DnsClientX through DNS-SD and multicast DNS, keep a live view of local services, and find a resolver's verified encrypted endpoints with DDR.
slug: discovery
collection: docs
layout: docs
---

## DNS-SD (RFC 6763)

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Cloudflare);

// Which service types does the domain advertise?
var types = await client.DiscoverServiceTypesAsync("example.com");

// Browse instances of one type, then read their SRV and TXT data
var services = await client.BrowseServicesAsync("http", "tcp", "example.com");
foreach (var service in services) {
    Console.WriteLine($"{service.InstanceName}: {service.Target}:{service.Port}");
}
```

```powershell
Find-DnsService -Domain example.com -ServiceTypes
Get-DnsService -Domain example.com -Service http -Protocol tcp -Resolve
```

SRV answers follow RFC 2782 weighted ordering.

## Multicast DNS (RFC 6762)

```csharp
using var mdns = new ClientX("224.0.0.251", DnsRequestFormat.Multicast) {
    EndpointConfiguration = { Port = 5353, TimeOut = 1500 }
};
var responses = await mdns.ResolveMulticastAllAsync("printer.local", DnsRecordType.A);
```

`ResolveMulticastAllAsync` collects every responder within the timeout. `BrowseServicesContinuousAsync` keeps a bounded, live view of local services with additions, updates, goodbyes and expiry, and drains cleanly on cancellation. Rediscover after network or interface changes, since multicast announcements can be lost.

## Designated encrypted resolvers (DDR)

DDR asks a plain IP resolver which encrypted endpoints it designates. DnsClientX keeps the discovery pinned to the original resolver and marks a candidate `Verified` only when its certificate chains to a trusted root and names the original resolver's IP.

```csharp
using var original = new ClientX("1.1.1.1", DnsRequestFormat.DnsOverUDP);
var candidates = await original.DiscoverDesignatedResolversAsync();

var designated = candidates.FirstOrDefault(c => c.Verification == DnsDesignatedResolverVerification.Verified);
if (designated is not null) {
    using var encrypted = new ClientX(designated.CreateConfiguration());
    var response = await encrypted.Resolve("example.com", DnsRecordType.A);
}
```

Discovery never changes the original client and never falls back to cleartext. DDR and the `Get-DnsDesignatedResolver` and `Receive-DnsService` cmdlets are merged in source and arrive with the next public release.

## Next steps

- [Transports and endpoints](/docs/dnsclientx/transports/)
- [About DnsClientX](/dnsclientx/)
