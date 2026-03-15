---
title: DNS Resolvers
description: Configuring DNS resolvers for DomainDetective.
slug: dns-resolvers
collection: docs
layout: docs
---

## Overview

DomainDetective uses the [DnsClientX](https://github.com/EvotecIT/DnsClientX) library for DNS resolution. You can configure which DNS resolvers to use for all queries.

## Default Behavior

By default, DomainDetective uses the system DNS resolver. For browser-based tools, it uses Cloudflare's DNS-over-HTTPS endpoint.

## Configuring a Single Resolver

```csharp
var healthCheck = new DomainHealthCheck();
healthCheck.DnsEndpoint = DnsEndpoint.CloudflareWireFormat;
```

## Available Resolvers

| Endpoint | Protocol | Provider |
|----------|----------|----------|
| `System` | UDP/TCP | OS default |
| `SystemTcp` | TCP | OS default |
| `CloudflareWireFormat` | DoH (wire) | Cloudflare |
| `Cloudflare` | DoH (JSON) | Cloudflare |
| `Google` | DoH | Google |
| `Quad9` | DoH | Quad9 |

## Browser Compatibility

When running in a browser (Blazor WASM), only DNS-over-HTTPS endpoints work because browsers cannot make raw UDP/TCP DNS queries. Use `DnsEndpoint.CloudflareWireFormat` for browser-based tools.
