---
title: DnsClientX
description: Use DnsClientX directly when you need DNS resolution primitives, provider selection, typed records, and DNSSEC-aware flows outside the higher-level DomainDetective analysis model.
slug: dnsclientx
collection: docs
layout: docs
---

DnsClientX is the lower-level DNS library and PowerShell module that powers DomainDetective resolver workflows. Reach for it when your problem is "query DNS precisely and control the resolver behavior" rather than "analyze a whole domain posture."

## Start Here

| Workflow | Best for | Guide |
| --- | --- | --- |
| .NET library | Services, apps, diagnostics, reusable DNS logic | [DnsClientX for .NET](/docs/dnsclientx/csharp/) |
| PowerShell module | Scripts, CI, operations automation, ad-hoc investigations | [DnsClientX for PowerShell](/docs/dnsclientx/powershell/) |
| Browser exploration | Testing record types and provider responses before coding | [DNS Query Playground](/tools/dns-query-playground/) |

## DNS Lane In DomainDetective

Use the DomainDetective-hosted DNS lane when you want to move between browser exploration, resolver guidance, and direct code examples without leaving the site.

- [DNS Query Playground](/tools/dns-query-playground/) for interactive record lookup and response inspection
- [DNS Resolvers](/docs/dns-resolvers/) for provider behavior and resolver strategy guidance
- [PowerShell Cmdlets](/docs/powershell-cmdlets/) for module-oriented DNS workflows inside DomainDetective
- [C# API Guide](/docs/csharp-api/) for higher-level DomainDetective integration patterns

## Generated Reference

- [.NET API reference](/api/dnsclientx/)
- [PowerShell cmdlet reference](/api/dnsclientx-powershell/)

## Install

```bash
dotnet add package DnsClientX
```

```powershell
Install-Module DnsClientX -Scope CurrentUser
```

## When To Use DnsClientX Instead Of DomainDetective

- You need one or a few raw DNS queries rather than a full domain assessment.
- You want direct control over resolver endpoints, transport, EDNS options, or DNSSEC request flags.
- You are building your own DNS workflows, diagnostics, or tooling on top of a reusable client.

## Related DomainDetective Docs

- [DNS Resolvers](/docs/dns-resolvers/)
- [C# API Guide](/docs/csharp-api/)
- [PowerShell Cmdlets](/docs/powershell-cmdlets/)
