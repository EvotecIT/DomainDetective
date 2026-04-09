---
title: DnsClientX Toolkit
description: DnsClientX entry points across the DomainDetective web workspace, PowerShell, and C#.
slug: dnsclientx
collection: docs
layout: docs
---

## DNS Lane

- [DNS Lookup](/tools/dns-lookup/) - Browser DNS workspace
- [DnsClientX DNS Workspace](/docs/dns-workspace/) - Browser workflow, focused views, and export
- [DNS Examples](/docs/dns-examples/) - Copy-ready PowerShell, C#, and CLI DNS workflows
- [DNS Resolvers](/docs/dns-resolvers/) - Resolver behavior and provider guidance
- [C# API Guide](/docs/csharp-api/) - Broader .NET usage around DomainDetective and DNS

## Overview

DnsClientX is the DNS engine that powers DomainDetective's browser DNS workspace and the direct DNS examples in the docs.

This page is the DNS landing area when you want to move between:

- the browser-safe `DNS Lookup` workspace in DomainDetective
- direct PowerShell DNS commands
- direct C# DNS queries
- resolver and benchmarking guidance

## Support Snapshot

The browser workspace and the local library do not expose the same transport surface:

- The browser workspace stays on browser-safe DNS-over-HTTPS resolver paths.
- Local DnsClientX workflows can use system DNS, UDP, TCP, DoT, and DoH.
- On .NET 8 and later, local DnsClientX workflows can also use DoH3 and DoQ without adding extra transport packages.
- Older targets keep the same API surface, but modern transports are reported as unsupported at runtime.

## Start In The Browser

Use [`/tools/dns-lookup/`](/tools/dns-lookup/) when you want:

- a quick browser-safe DNS view for one domain
- record-type presets such as `Starter`, `Web`, `Mail`, and `Zone`
- easy switching between supported browser DoH resolvers
- a focused export you can paste into notes or tickets

That workspace is documented in the [DnsClientX DNS Workspace](/docs/dns-workspace/) guide.

It is intentionally not a full transport matrix for DnsClientX. If you want DoT, DoH3, DoQ, explicit endpoint strings, benchmarking, or saved resolver selection reuse, move to the local PowerShell, CLI, or C# paths.

## Move To PowerShell

Install the module:

```powershell
Install-Module DnsClientX -Scope CurrentUser
Import-Module DnsClientX
```

Run a direct query:

```powershell
Resolve-Dns -Name 'contoso.com' -Type A, AAAA, MX -DnsProvider Cloudflare | Format-Table
```

Query a specific hostname:

```powershell
Resolve-Dns -Name '_dmarc.contoso.com' -Type TXT -DnsProvider Google | Format-Table
```

Benchmark resolvers:

```powershell
Test-DnsBenchmark -Name 'contoso.com' -DnsProvider Cloudflare, Google, Quad9 -Attempts 3 |
    Sort-Object Rank | Format-Table Target, SuccessPercent, AverageMs, Rank, IsRecommended
```

Use modern explicit endpoints on .NET 8+:

```powershell
Resolve-Dns -Name 'contoso.com' -Type A `
    -ResolverEndpoint 'doq@dns.quad9.net:853','doh3@https://dns.quad9.net/dns-query' `
    -ResolverStrategy FirstSuccess | Format-Table
```

## Move To C#

Install the package:

```bash
dotnet add package DnsClientX
```

Run a direct query:

```csharp
using DnsClientX;

var response = await ClientX.QueryDns("contoso.com", DnsRecordType.A, DnsEndpoint.Cloudflare);
foreach (var answer in response.Answers) {
    Console.WriteLine($"{answer.Name} -> {answer.Data}");
}
```

Run multiple record types:

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Google);
var responses = await client.Resolve("contoso.com", new[] { DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.MX });
responses.DisplayTable();
```

Use a modern explicit endpoint on .NET 8+:

```csharp
using DnsClientX;

var response = await ClientX.QueryDns(
    new ResolveDnsRequest {
        Names = new[] { "contoso.com" },
        RecordTypes = new[] { DnsRecordType.A },
        ResolverEndpoints = new[] { "doh3@https://dns.quad9.net/dns-query", "doq@dns.quad9.net:853" },
        ResolverStrategy = MultiResolverStrategy.FirstSuccess
    });
```

## Today vs Later

Today, the DomainDetective website uses DnsClientX as the DNS engine behind the browser workspace and the local workflow guidance.

Later, this documentation lane can expand into a fuller DNS area with:

- more DnsClientX-focused examples
- direct DNS API documentation links
- deeper resolver and benchmarking guides
- clearer transport-by-runtime support notes

## Related Reading

- [DnsClientX DNS Workspace](/docs/dns-workspace/)
- [DNS Resolvers](/docs/dns-resolvers/)
- [C# API Guide](/docs/csharp-api/)
- [PowerShell Cmdlets](/docs/powershell-cmdlets/)
- [DnsClientX on GitHub](https://github.com/EvotecIT/DnsClientX)
