---
title: Quick Start
description: Get started with DomainDetective in minutes.
slug: quickstart
collection: docs
layout: docs
---

## Install

### NuGet Package

```bash
dotnet add package DomainDetective
```

### PowerShell Module

```powershell
Install-Module DomainDetective -Scope CurrentUser
```

## Basic Usage

### C#

```csharp
using DomainDetective;

var healthCheck = new DomainHealthCheck();

// Check SPF
await healthCheck.VerifySPF("example.com");
Console.WriteLine($"SPF Record: {healthCheck.SpfAnalysis.SpfRecord}");

// Check DMARC
await healthCheck.VerifyDMARC("example.com");
Console.WriteLine($"DMARC Policy: {healthCheck.DmarcAnalysis.PolicyShort}");

// Check MX
await healthCheck.VerifyMX("example.com");
foreach (var mx in healthCheck.MXAnalysis.MxRecords) {
    Console.WriteLine($"MX: {mx}");
}
```

### PowerShell

```powershell
# Import the module
Import-Module DomainDetective

# Run a comprehensive check
$check = Get-DomainHealthCheck -Domain "example.com"

# View results
$check.SpfAnalysis
$check.DmarcAnalysis
$check.MXAnalysis
```

## Next Steps

- [C# API Guide](/docs/csharp-api/) - Detailed C# usage
- [Configuration](/docs/configuration/) - Customize behavior
- [Online Tools](/tools/) - Try in your browser
