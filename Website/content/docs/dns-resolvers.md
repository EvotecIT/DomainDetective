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

For local DnsClientX usage, the transport surface is broader:

- `System` and `SystemTcp` cover classic resolver paths.
- DoH, DoT, and explicit endpoint strings are available locally.
- On .NET 8 and later, DoH3 and DoQ stay in the core package with no extra transport package required.
- The browser workspace still stays on DoH because browsers do not expose raw UDP, TCP, DoT, or DoQ sockets to the site.

## Configuring a Single Resolver

```csharp
var healthCheck = new DomainHealthCheck();
healthCheck.DnsEndpoint = DnsEndpoint.CloudflareWireFormat;
```

## Available Resolvers

| Endpoint | Protocol | Local | Browser workspace |
|----------|----------|-------|-------------------|
| `System` | UDP/TCP fallback | Yes | No |
| `SystemTcp` | TCP | Yes | No |
| `CloudflareWireFormat` | DoH (wire) | Yes | No |
| `Cloudflare` | DoH (JSON) | Yes | Yes |
| `Google` | DoH | Yes | Yes |
| `Quad9` | DoH | Yes | No |
| `CloudflareQuic` | DoQ | Yes on .NET 8+ | No |
| `GoogleQuic` | DoQ | Yes on .NET 8+ | No |
| `Quad9Http3` | DoH3 | Yes on .NET 8+ | No |
| `Quad9Quic` | DoQ | Yes on .NET 8+ | No |

## Explicit Endpoint Syntax

Local DnsClientX workflows also accept explicit endpoint strings:

- `udp@1.1.1.1:53`
- `tcp@9.9.9.9:53`
- `dot@dns.quad9.net:853`
- `doh@https://dns.google/dns-query`
- `doh3@https://dns.quad9.net/dns-query`
- `doq@dns.quad9.net:853`

## Browser Compatibility

When running in a browser (Blazor WASM), only DNS-over-HTTPS endpoints work because browsers cannot make raw UDP, TCP, DoT, or DoQ DNS queries. The DomainDetective website currently keeps the browser-safe DNS workspace focused on `Google DNS` and `Cloudflare DNS`, while fuller resolver choice stays in the local DnsClientX workflows.
