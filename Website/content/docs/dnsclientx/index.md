---
title: DnsClientX Toolkit
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

## DNS Lane In DomainDetective

Use the DomainDetective docs when you want to understand how DnsClientX fits into the broader DNS analysis workflow without leaving the documentation surface.

- [DNS Resolvers](/docs/dns-resolvers/) for provider behavior and resolver strategy guidance
- [PowerShell Guide](/docs/powershell-cmdlets/) for module-oriented DNS workflows inside DomainDetective
- [.NET SDK Guide](/docs/csharp-api/) for higher-level DomainDetective integration patterns

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
