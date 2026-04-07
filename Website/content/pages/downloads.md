---
title: Downloads & Installation
description: Install DomainDetective via NuGet, PowerShell Gallery, or .NET CLI.
slug: downloads
collection: pages
layout: page
---

## Installation

### C# / NuGet

```bash
dotnet add package DomainDetective
```

### PowerShell

```powershell
Install-Module DomainDetective -Scope CurrentUser
```

### CLI Tool

```bash
dotnet tool install -g DomainDetective.CLI
```

### Browser

No installation needed! Visit the [online tools](/tools/) to analyze domains directly in your browser.

## Requirements

- **.NET Library**: .NET 8.0+ or .NET Framework 4.7.2+
- **PowerShell Module**: PowerShell 5.1+ or PowerShell 7.0+
- **CLI Tool**: .NET 8.0+ runtime
- **Browser Tools**: Any modern browser with JavaScript enabled

## Related DNS Client Package

If you only need direct DNS querying instead of full DomainDetective analysis, use DnsClientX:

```bash
dotnet add package DnsClientX
```

```powershell
Install-Module DnsClientX -Scope CurrentUser
```

- [DnsClientX product page](/products/dnsclientx/)
- [DnsClientX .NET API](/api/dnsclientx/)
- [DnsClientX PowerShell API](/api/dnsclientx-powershell/)
