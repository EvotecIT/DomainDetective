---
title: PowerShell Cmdlets
description: Using DomainDetective from PowerShell.
slug: powershell-cmdlets
collection: docs
layout: docs
---

## Installation

```powershell
Install-Module DomainDetective -Scope CurrentUser
```

## Basic Usage

```powershell
Import-Module DomainDetective

# Run a comprehensive domain health check
$check = Get-DomainHealthCheck -Domain "example.com"

# View specific results
$check.SpfAnalysis
$check.DmarcAnalysis
$check.MXAnalysis
$check.DnsSecAnalysis
```

## Individual Checks

```powershell
# SPF
$check = Get-DomainHealthCheck -Domain "example.com" -Type SPF

# DKIM with selectors
$check = Get-DomainHealthCheck -Domain "example.com" -Type DKIM -DkimSelectors "default", "selector1"

# DNSSEC
$check = Get-DomainHealthCheck -Domain "example.com" -Type DNSSEC
```

## Batch Analysis

```powershell
$domains = "example.com", "contoso.com", "evotec.xyz"
$results = $domains | ForEach-Object {
    Get-DomainHealthCheck -Domain $_ -Type SPF, DMARC
}
$results | Format-Table Domain, SpfAnalysis, DmarcAnalysis
```

## API Reference

See the [full PowerShell API reference](/api/powershell/) for generated cmdlet and type documentation.
