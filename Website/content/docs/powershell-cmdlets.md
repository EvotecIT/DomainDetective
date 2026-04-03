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
$check = Test-DomainHealth -DomainName "example.com"

# View specific results
$check.SpfAnalysis
$check.DmarcAnalysis
$check.MXAnalysis
$check.DnsSecAnalysis
```

## Individual Checks

```powershell
# SPF
$check = Test-DomainHealth -DomainName "example.com" -HealthCheckType SPF

# DKIM with selectors
$check = Test-DomainHealth -DomainName "example.com" -HealthCheckType DKIM -DkimSelectors "default", "selector1"

# DNSSEC
$check = Test-DomainHealth -DomainName "example.com" -HealthCheckType DNSSEC
```

## Batch Analysis

```powershell
$domains = "example.com", "contoso.com", "evotec.xyz"
$results = $domains | ForEach-Object {
    Test-DomainHealth -DomainName $_ -HealthCheckType SPF, DMARC
}
$results | Format-Table Domain, SpfAnalysis, DmarcAnalysis
```

## API Reference

See the [full PowerShell API reference](/api/powershell/) for generated cmdlet and type documentation.
