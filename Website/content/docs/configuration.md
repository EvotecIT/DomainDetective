---
title: Runtime Configuration
description: Configure DomainDetective behavior, defaults, and execution settings.
slug: configuration
collection: docs
layout: docs
---

## DNS Configuration

### DNS Endpoint

Set the DNS resolver endpoint:

```csharp
var healthCheck = new DomainHealthCheck();
healthCheck.DnsEndpoint = DnsEndpoint.CloudflareWireFormat; // DNS-over-HTTPS
```

Available endpoints:
- `DnsEndpoint.System` - System default resolver
- `DnsEndpoint.SystemTcp` - System resolver via TCP
- `DnsEndpoint.CloudflareWireFormat` - Cloudflare DoH (wire format)
- `DnsEndpoint.Cloudflare` - Cloudflare DoH (JSON)
- `DnsEndpoint.Google` - Google Public DNS
- `DnsEndpoint.Quad9` - Quad9 DNS

### Multiple Resolvers

```csharp
healthCheck.DnsEndpoints.Add(DnsEndpoint.Google);
healthCheck.DnsEndpoints.Add(DnsEndpoint.Quad9);
healthCheck.MultiResolverStrategy = MultiResolverStrategy.All;
```

## HTTP Client

```csharp
healthCheck.HttpClientFactory = myHttpClientFactory;
```

## DNSBL Lists

DomainDetective includes a built-in DNSBL list. To use a custom list:

```csharp
healthCheck.LoadDNSBL("path/to/custom-dnsbl.json");
```

## DNS Propagation

```csharp
healthCheck.DnsPropagationMaxServers = 60;
healthCheck.DnsPropagationMaxParallelism = 20;
healthCheck.DnsPropagationIncludeGeo = true;
```
