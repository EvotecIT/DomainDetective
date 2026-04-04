---
title: DnsClientX for PowerShell
description: Use the DnsClientX PowerShell module for direct DNS lookups, provider comparison, full response inspection, and DNSSEC-aware scripts.
slug: powershell
collection: docs
layout: docs
---

## Basic Query

```powershell
Resolve-Dns -Name 'evotec.pl' -Type A -DnsProvider Cloudflare | Format-Table
```

## Compare Providers

```powershell
Resolve-Dns -Name 'evotec.pl' -Type A -DnsProvider Cloudflare,Google -ResolverStrategy FirstSuccess | Format-Table
```

## Full Response

```powershell
$response = Resolve-Dns -Name 'evotec.pl' -Type MX -DnsProvider Cloudflare -FullResponse

$response.Questions | Format-Table
$response.Answers | Format-Table
$response.Authorities | Format-Table
$response.Additional | Format-Table
```

## DNSSEC-Aware Query

```powershell
Resolve-Dns -Name 'evotec.pl' -Type DS -DnsProvider Cloudflare -RequestDnsSec -ValidateDnsSec | Format-Table
```

## Direct Resolver Endpoints

```powershell
Resolve-Dns -Name 'evotec.pl' -Type TXT -ResolverEndpoint '1.1.1.1:53','https://dns.google/dns-query' -ResolverStrategy FirstSuccess | Format-Table
```

## Need Parameter-Level Reference?

Use the generated [DnsClientX PowerShell API reference](/api/dnsclientx-powershell/) when you want exact parameters, examples, aliases, and current help output from the module source.
