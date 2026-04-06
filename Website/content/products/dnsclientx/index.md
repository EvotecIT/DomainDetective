---
title: DnsClientX
description: Modern DNS client for .NET and PowerShell, documented inside DomainDetective.dev with generated API reference and direct DNS tooling.
slug: dnsclientx
collection: products
layout: page
---

DnsClientX is the DNS engine behind large parts of DomainDetective. If you want raw DNS resolution, provider control, DNSSEC-aware queries, EDNS options, or direct DNS automation without the higher-level domain analysis layer, this is the product surface to start with.

## Choose Your Entry Point

| Entry point | Best for | Start here |
| --- | --- | --- |
| DnsClientX for .NET | App code, services, diagnostics, CLI tools, reusable DNS workflows | [C# guide](/docs/dnsclientx/csharp/) |
| DnsClientX for PowerShell | Scripts, GitHub Actions, CI checks, incident response, operations automation | [PowerShell guide](/docs/dnsclientx/powershell/) |
| DNS query playground | Exploring records interactively before writing code | [Open tool](/dns-query-playground/) |

## Install

```bash
dotnet add package DnsClientX
```

```powershell
Install-Module DnsClientX -Scope CurrentUser
```

## What It Gives You

- Direct queries across UDP, TCP, DNS over HTTPS, DNS over TLS, DNS over QUIC, and other resolver transports.
- Typed record parsing when raw answer strings are not enough.
- Multi-resolver strategies when you want to compare providers or race for the first successful answer.
- EDNS options including client subnet scenarios.
- DNSSEC-aware request and validation flows.

## Typical C# Usage

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Cloudflare);
DnsResponse response = await client.Resolve("evotec.pl", DnsRecordType.MX, typedRecords: true);

foreach (var answer in response.Answers) {
    Console.WriteLine($"{answer.Type}: {answer.Data}");
}
```

## Typical PowerShell Usage

```powershell
Resolve-Dns -Name 'evotec.pl' -Type A -DnsProvider Cloudflare | Format-Table
```

```powershell
Resolve-Dns -Name 'evotec.pl' -Type MX -DnsProvider Cloudflare,Google -ResolverStrategy FirstSuccess | Format-Table
```

## Generated API Reference

| Surface | URL |
| --- | --- |
| DnsClientX C# API | [Open .NET API reference](/api/dnsclientx/) |
| DnsClientX PowerShell cmdlets | [Open PowerShell API reference](/api/dnsclientx-powershell/) |

## Next Steps

- [DnsClientX overview](/docs/dnsclientx/)
- [C# guide](/docs/dnsclientx/csharp/)
- [PowerShell guide](/docs/dnsclientx/powershell/)
- [DNS query playground](/dns-query-playground/)
- [DnsClientX source repository](https://github.com/EvotecIT/DnsClientX)
