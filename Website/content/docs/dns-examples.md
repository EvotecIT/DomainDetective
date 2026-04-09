---
title: DNS Examples
description: Practical DnsClientX and DomainDetective DNS examples for browser, PowerShell, C#, and CLI workflows.
slug: dns-examples
collection: docs
layout: docs
---

## DNS Lane

- [DNS Lookup](/tools/dns-lookup/) - Browser DNS workspace
- [DnsClientX Toolkit](/docs/dnsclientx/) - DNS entry points across browser, PowerShell, and C#
- [DnsClientX DNS Workspace](/docs/dns-workspace/) - Browser workflow, focused views, local host targets, and export
- [DNS Resolvers](/docs/dns-resolvers/) - Resolver behavior and provider guidance

## Overview

Use this page when you already know you want concrete DNS commands or code.

It sits between the browser `DNS Lookup` workspace and the broader API guides:

- start in the browser when you want a quick focused DNS view
- come here when you want copy-ready local examples
- move to the full API guides when you need the broader DomainDetective surface

## PowerShell Examples

Install the DNS module:

```powershell
Install-Module DnsClientX -Scope CurrentUser
Import-Module DnsClientX
```

Query common apex records:

```powershell
Resolve-Dns -Name 'contoso.com' -Type A, AAAA, MX -DnsProvider Cloudflare | Format-Table
```

Query a mail-policy hostname:

```powershell
Resolve-Dns -Name '_dmarc.contoso.com' -Type TXT -DnsProvider Google | Format-Table
```

Query a DKIM selector:

```powershell
Resolve-Dns -Name 'default._domainkey.contoso.com' -Type TXT, CNAME -DnsProvider Cloudflare | Format-Table
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

## C# Examples

Install the package:

```bash
dotnet add package DnsClientX
```

Query one record type:

```csharp
using DnsClientX;

var response = await ClientX.QueryDns("contoso.com", DnsRecordType.A, DnsEndpoint.Cloudflare);
foreach (var answer in response.Answers) {
    Console.WriteLine($"{answer.Name} -> {answer.Data}");
}
```

Query multiple focused record types:

```csharp
using DnsClientX;

var recordTypes = new[] { DnsRecordType.TXT, DnsRecordType.CNAME };
foreach (var recordType in recordTypes) {
    var response = await ClientX.QueryDns("default._domainkey.contoso.com", recordType, DnsEndpoint.Google);
    foreach (var answer in response.Answers) {
        Console.WriteLine($"{recordType}: {answer.Name} -> {answer.Data}");
    }
}
```

Query through a modern explicit endpoint set on .NET 8+:

```csharp
using DnsClientX;

var responses = await ClientX.QueryDns(
    new ResolveDnsRequest {
        Names = new[] { "contoso.com" },
        RecordTypes = new[] { DnsRecordType.A, DnsRecordType.AAAA },
        ResolverEndpoints = new[] { "doh3@https://dns.quad9.net/dns-query", "doq@dns.quad9.net:853" },
        ResolverStrategy = MultiResolverStrategy.FirstSuccess
    });
```

Use the DomainDetective DNS inventory:

```csharp
using DomainDetective;

var healthCheck = new DomainHealthCheck();
await healthCheck.VerifyDnsInventoryAsync("contoso.com");

foreach (var query in healthCheck.DnsInventoryAnalysis.Queries) {
    Console.WriteLine($"{query.RecordType}: {query.Status} ({query.Records.Count} records)");
}
```

## CLI Example

Use the broader DomainDetective DNS inventory from the CLI:

```bash
dotnet tool install -g DomainDetective.CLI
domaindetective check contoso.com --checks DNSINVENTORY
```

## When To Use Which Path

- Use [DNS Lookup](/tools/dns-lookup/) for a quick browser-safe answer view
- Use DnsClientX PowerShell or C# when you need specific hostnames, typed records, repeatable DNS automation, or modern local transports
- Use the wider DomainDetective API or CLI when you want DNS as part of full domain posture analysis

## Related Reading

- [DnsClientX Toolkit](/docs/dnsclientx/)
- [DnsClientX DNS Workspace](/docs/dns-workspace/)
- [DNS Resolvers](/docs/dns-resolvers/)
- [C# API Guide](/docs/csharp-api/)
- [PowerShell Cmdlets](/docs/powershell-cmdlets/)
