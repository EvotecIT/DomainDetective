---
title: DnsClientX DNS Workspace
description: Use DomainDetective's DNS Lookup page as a DnsClientX-oriented DNS workspace.
slug: dns-workspace
collection: docs
layout: docs
---

## DNS Lane

- [DNS Lookup](/tools/dns-lookup/) - Browser DNS workspace
- [DnsClientX Toolkit](/docs/dnsclientx/) - DNS entry points across browser, PowerShell, and C#
- [DNS Examples](/docs/dns-examples/) - Copy-ready PowerShell, C#, and CLI DNS workflows
- [DNS Resolvers](/docs/dns-resolvers/) - Resolver behavior and provider guidance
- [C# API Guide](/docs/csharp-api/) - Broader .NET usage around DomainDetective and DNS

## Overview

The `/tools/dns-lookup/` page is the DnsClientX-oriented DNS workspace in the DomainDetective web edition.

It keeps the browser experience simple:

- Run the standard DomainDetective DNS inventory in the browser
- Focus the answer view on the record types you care about
- Choose the browser-safe DoH resolver used for the live query
- Jump between common `Starter`, `Web`, `Mail`, and `Zone` presets
- Keep a separate local-only host target like `_dmarc`, `_mta-sts`, or `default._domainkey`
- Show the raw records that came back for that focused view
- Copy the focused result set as JSON or zone-style text
- Point you to the direct DnsClientX workflows for PowerShell and C#

That gives you one DNS entry point instead of separate overlapping tools.

## What The Browser Workspace Does

The browser version of DNS Lookup runs the DomainDetective DNS inventory, lets you choose the browser-safe resolver for the live query, and then narrows the visible result set to the record types you ask for in the optional focus box.

Examples:

- `A, AAAA`
- `MX, TXT`
- `NS, SOA, CAA`

Current browser resolver choices:

- `Google DNS`
- `Cloudflare DNS`

This is intentionally a focused workspace, not a full custom DNS client UI. It is meant to help you inspect the DNS surface quickly, then step into local DnsClientX usage when you want deeper control.

The optional host field is local-workflow oriented. It does not replace the browser inventory subject. Instead, it retargets the copyable DnsClientX commands and examples toward common off-apex names such as `_dmarc.contoso.com` or `default._domainkey.contoso.com`.

## When To Stay In The Browser

Use the web workspace when you want:

- A quick posture-oriented DNS view for one domain
- A focused answer view for common record types
- A quick resolver switch between browser-safe DoH providers
- One-click preset pivots for common DNS jobs
- A quick export of the focused DNS view into notes or tickets
- A browser-safe workflow that still matches the DD DNS engine

## When To Switch To DnsClientX Locally

Switch to DnsClientX locally when you want:

- Explicit resolver selection
- Typed DNS records in C#
- Batch DNS workflows
- Benchmarking multiple resolvers
- System DNS, DoH, DoT, or other provider choices
- DoH3 or DoQ on .NET 8 and later
- Explicit resolver endpoint strings such as `doq@dns.quad9.net:853`

## Transport Boundaries

The browser workspace is intentionally narrower than the local library:

- Browser: browser-safe DoH resolvers only
- Local DnsClientX: UDP, TCP, DoH, DoT, and built-in resolver families
- Local DnsClientX on .NET 8+: DoH3 and DoQ in the core package

That split keeps the site behavior honest while preserving the fuller transport surface in PowerShell, CLI, and C#.

## C# Quick Start

Install the package:

```bash
dotnet add package DnsClientX
```

Run a focused DNS query:

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

using var client = new ClientX(DnsEndpoint.Cloudflare);
var recordTypes = new[] { DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.MX };
var responses = await client.Resolve("contoso.com", recordTypes);
responses.DisplayTable();
```

## PowerShell Quick Start

Install the module:

```powershell
Install-Module DnsClientX -Scope CurrentUser
Import-Module DnsClientX
```

Run focused DNS queries:

```powershell
Resolve-Dns -Name 'contoso.com' -Type A, AAAA, MX -DnsProvider Cloudflare | Format-Table
```

Compare resolvers:

```powershell
Test-DnsBenchmark -Name 'contoso.com' -DnsProvider Cloudflare, Google, Quad9 -Attempts 3 |
    Sort-Object Rank | Format-Table Target, SuccessPercent, AverageMs, Rank, IsRecommended
```

## DomainDetective CLI Path

If you want the broader DD DNS inventory from the command line, use the DomainDetective CLI:

```bash
dotnet tool install -g DomainDetective.CLI
domaindetective check contoso.com --checks DNSINVENTORY
```

That keeps the DNS workspace aligned with the rest of the DomainDetective toolchain, while DnsClientX stays the lower-level DNS engine when you want direct control.

## Related Reading

- [DNS Resolvers](/docs/dns-resolvers/)
- [CLI Usage](/docs/cli-usage/)
- [C# API Guide](/docs/csharp-api/)
- [DnsClientX on GitHub](https://github.com/EvotecIT/DnsClientX)
