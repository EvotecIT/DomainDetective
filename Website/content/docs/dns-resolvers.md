---
title: DNS Resolvers
description: Configuring DNS resolvers for DomainDetective.
slug: dns-resolvers
collection: docs
layout: docs
---

## DNS Lane

- [DNS Lookup](/tools/dns-lookup/) - Browser DNS workspace
- [DnsClientX Toolkit](/docs/dnsclientx/) - DNS entry points across browser, PowerShell, and C#
- [DnsClientX DNS Workspace](/docs/dns-workspace/) - Browser workflow, focused views, local host targets, and export
- [DNS Examples](/docs/dns-examples/) - Copy-ready PowerShell, C#, and CLI DNS workflows
- [C# API Guide](/docs/csharp-api/) - Broader .NET usage around DomainDetective and DNS

## Overview

DomainDetective uses the [DnsClientX](https://github.com/EvotecIT/DnsClientX) library for DNS resolution. You can configure which DNS resolvers to use for all queries.

## Default Behavior

By default, DomainDetective uses the system DNS resolver. For browser-based tools, it uses browser-safe DNS-over-HTTPS resolver paths instead of raw UDP or TCP DNS.

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

When running in a browser (Blazor WASM), only DNS-over-HTTPS endpoints work because browsers cannot make raw UDP/TCP DNS queries. The DomainDetective website currently keeps the browser-safe DNS workspace focused on `Google DNS` and `Cloudflare DNS`, while fuller resolver choice stays in the local DnsClientX workflows.
