---
title: Resolver Strategy
description: Choose and configure DNS resolvers for DomainDetective and DnsClientX-backed workflows.
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

DomainDetective uses the [DnsClientX library](https://github.com/EvotecIT/DnsClientX) for DNS resolution. You can configure which DNS resolvers to use for all queries, or drop down to the dedicated [DnsClientX product docs](/products/dnsclientx/) when you need direct DNS workflows outside the full DomainDetective analysis model.

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

## ChatGPT Website Tool

The [Raw DNS Query playground](/tools/raw-dns-query/) exposes the read-only `query_dns_records` Website Tool in supported browsers. ChatGPT can request one public DNS name and one supported record type through the existing browser workflow. The page switches to the Google DNS-over-HTTPS resolver, clears EDNS client-subnet and DNSSEC options, and leaves the complete visible result in the playground.

The tool rejects local names, IP-like inputs, malformed labels, and unsupported record types. Its machine-readable response is capped at ten answers and 1,500 characters; a larger DNS response remains available in the visible page and is marked as truncated in the tool result. A caller can cancel the active network request. No hosted DomainDetective analysis API or authenticated workflow is involved.
