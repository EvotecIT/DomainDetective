---
title: Transports and endpoints
description: Choose UDP, TCP, DNS over TLS, HTTPS, HTTP/3 or QUIC in DnsClientX, write explicit endpoints and DNS stamps, and check what the current runtime supports.
slug: transports
collection: docs
layout: docs
---

DnsClientX keeps every transport behind one client. Built-in profiles cover the common public resolvers, and an explicit endpoint string reaches anything else. Modern transports ship in the core package with no extra dependencies; privacy transports are optional packages so the core stays dependency-free.

## Supported transports

| Transport | Request format | Notes |
| --- | --- | --- |
| UDP | `DnsOverUDP` | Falls back to TCP automatically when an answer is truncated. |
| TCP | `DnsOverTCP` | Persistent, pipelined sessions; required for zone transfers and updates. |
| DNS over TLS | `DnsOverTLS` | RFC 7858 with pooled sessions and the `dot` ALPN on modern .NET. |
| DNS over HTTPS | `DnsOverHttps`, `DnsOverHttpsPOST`, `DnsOverHttpsJSON` | RFC 8484 wire format over GET or POST, or a provider's JSON API. |
| DNS over HTTP/3 | `DnsOverHttp3` | .NET 8 and .NET 10, no extra packages. |
| DNS over QUIC | `DnsOverQuic` | RFC 9250 on .NET 8 and .NET 10 when the runtime exposes QUIC. |
| DNS over gRPC | `DnsOverGrpc` | For resolvers that publish a gRPC DNS service; capability is reported at runtime. |
| Multicast DNS | `Multicast` | mDNS queries and DNS-SD browsing on the local link. |

On .NET Standard 2.0 and .NET Framework 4.7.2 the API is the same, and modern transports report themselves as unsupported at runtime instead of pulling in another QUIC stack.

## Built-in profiles

```csharp
using DnsClientX;

using var cloudflare = new ClientX(DnsEndpoint.Cloudflare);        // DoH JSON
using var google = new ClientX(DnsEndpoint.GoogleWireFormat);      // RFC 8484 wire format
using var quad9 = new ClientX(DnsEndpoint.Quad9Quic);              // DNS over QUIC
using var system = new ClientX(DnsEndpoint.System);                // the operating system's resolvers

var response = await quad9.Resolve("evotec.pl", DnsRecordType.MX);
```

Profiles include filtering variants (`CloudflareFamily`, `OpenDNSFamily`, `AdGuardFamily`), wire-format and HTTP/3 variants, `Quad9ECS` for client-subnet answers and `RootServer` for iterative resolution from the root.

## Explicit endpoint syntax

The library, the PowerShell module and the CLI share one endpoint parser:

| Transport | Example |
| --- | --- |
| UDP | `udp@1.1.1.1:53` |
| TCP | `tcp@9.9.9.9:53` |
| DoT | `dot@dns.quad9.net:853` |
| DoH | `doh@https://dns.google/dns-query` |
| DoH3 | `doh3@https://dns.quad9.net/dns-query` |
| DoQ | `doq@dns.quad9.net:853` |
| DNS stamp | `sdns://AgUAAAAAAAAABzEuMS4xLjEAGm1vemlsbGEuY2xvdWRmbGFyZS1kbnMuY29tCi9kbnMtcXVlcnk` |

```powershell
Resolve-Dns -Name evotec.pl -Type A `
  -ResolverEndpoint 'udp@1.1.1.1:53','doh@https://dns.google/dns-query' `
  -ResolverStrategy FirstSuccess
```

Stamps map into the same endpoint model for plain DNS, DoH, DoT and DoQ. DNSCrypt and ODoH stamps are detected and rejected with a clear unsupported-protocol error rather than being reinterpreted.

## Check what the runtime supports

```powershell
Get-DnsTransportCapability
Get-DnsTransportCapability -ModernOnly
```

In .NET, `DnsTransportCapabilities` answers the same question before you send a query. Saved probe and benchmark results also record these capabilities, so an unsupported transport is not mistaken for a failing resolver.

## Privacy transports

Oblivious DoH (RFC 9230) and DNSCrypt v2 are separate packages, `DnsClientX.Odoh` and `DnsClientX.DnsCrypt`. They are merged in source and arrive with the next public release. Neither falls back to direct DoH or plaintext DNS when an exchange fails.

## Next steps

- [Multi-resolver and benchmarking](/docs/dnsclientx/multi-resolver/)
- [DNSSEC and resolution](/docs/dnsclientx/dnssec/)
- [Try any resolver in the DNS playground](/tools/raw-dns-query/)
