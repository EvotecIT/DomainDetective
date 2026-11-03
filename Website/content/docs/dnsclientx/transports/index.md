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

The next release adds CleanBrowsing (`CleanBrowsingSecurity`, `CleanBrowsingAdult`, `CleanBrowsingFamily`), Control D (`ControlD`, `ControlDMalware`, `ControlDAds`, `ControlDFamily`), `ComodoSecureDns` and `DnsWatch`. Comodo and DNS.WATCH are plain UDP with the usual TCP fallback, so their queries are not encrypted.

### Choose a profile's transport

From the next release, a profile keeps its filtering policy and TLS identity while you choose how to reach it. Each provider publishes its own set of UDP, TCP, DoT, DoH and DoQ endpoints, and a combination the provider does not publish fails with an explicit error instead of silently switching.

```powershell
Resolve-Dns -Name evotec.pl -DnsProvider AdGuardFamily -ProviderTransport DnsOverQuic
Resolve-Dns -Name evotec.pl -DnsProvider Cloudflare -ProviderTransport DnsOverTLS
```

```text
DnsClientX.Cli --endpoint ControlDAds --provider-transport DnsOverQuic evotec.pl
```

In .NET, `new Configuration(provider, requestFormat)` makes the same choice. Overrides for `System`, `SystemTcp` and `RootServer` keep the operating system's resolver policy or root iteration, so they need a single-provider query.

### Personal NextDNS profiles

The `NextDNS` profile is the generic resolver. To use your own NextDNS configuration, pass its endpoint explicitly, for example `doh@https://dns.nextdns.io/abc123` or `dot@abc123.dns.nextdns.io:853`. The same works for a personal Control D URL.

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

Stamps map into the same endpoint model for plain DNS, DoH, DoT and DoQ. DNSCrypt and ODoH stamps are never reinterpreted as another transport: the core endpoint parser rejects them, and the privacy providers below consume them instead.

## Check what the runtime supports

```powershell
Get-DnsTransportCapability
Get-DnsTransportCapability -ModernOnly
```

In .NET, `DnsTransportCapabilities` answers the same question before you send a query. Saved probe and benchmark results also record these capabilities, so an unsupported transport is not mistaken for a failing resolver.

## Privacy transports

Oblivious DoH (RFC 9230) and DNSCrypt v2 are separate packages, `DnsClientX.Odoh` and `DnsClientX.DnsCrypt`. They are merged in source and arrive with the next public release. Neither falls back to direct DoH or plaintext DNS when an exchange fails.

You configure them from role-specific DNS stamps or HTTPS endpoints: a DNSCrypt resolver stamp with an optional anonymizing relay, or an ODoH target with its required relay. You choose the provider DLL explicitly, so the core package and CLI gain no cryptography dependencies.

```powershell
$transport = New-DnsPrivacyTransport -ProviderPath ./DnsClientX.Odoh.dll `
  -Resolver https://target.example/dns-query -Relay https://relay.example/dns-query
try {
    Resolve-Dns example.com -Configuration $transport.CreateConfiguration() -FullResponse
} finally {
    $transport.Dispose()
}
```

The CLI takes the same inputs through `--privacy-provider`, `--privacy-resolver` and `--privacy-relay`, and `--stamp-info` decodes a privacy stamp without loading any provider.

## Next steps

- [Multi-resolver and benchmarking](/docs/dnsclientx/multi-resolver/)
- [DNSSEC and resolution](/docs/dnsclientx/dnssec/)
- [Try any resolver in the DNS playground](/tools/raw-dns-query/)
