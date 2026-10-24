---
title: Install DomainDetective
description: Pick the surface that fits your work. Every one runs the same DomainDetective engine.
slug: downloads
collection: pages
layout: downloads
---

## Requirements

- **.NET Library**: .NET 8.0+ or .NET Framework 4.7.2+
- **PowerShell Module**: PowerShell 5.1+ or PowerShell 7.0+
- **CLI Tool**: .NET 8.0+ runtime
- **Browser Tools**: Any modern browser with JavaScript enabled

## Build from source

DomainDetective is MIT licensed. Clone the repository to build the library, PowerShell module and CLI yourself, or to contribute a fix.

```bash
git clone https://github.com/EvotecIT/DomainDetective.git
cd DomainDetective
dotnet build DomainDetective.sln -c Release
```

## Related DNS client package

If you only need direct DNS querying instead of full DomainDetective analysis, use DnsClientX:

```bash
dotnet add package DnsClientX
```

```powershell
Install-Module DnsClientX -Scope CurrentUser
```

- [DnsClientX product page](/dnsclientx/)
- [DnsClientX .NET API](/api/dnsclientx/)
- [DnsClientX PowerShell API](/api/dnsclientx-powershell/)
