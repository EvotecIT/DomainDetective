---
title: .NET SDK Guide
description: Build DomainDetective into your .NET applications and analysis workflows.
slug: csharp-api
collection: docs
layout: docs
---

## Installation

```bash
dotnet add package DomainDetective
```

## Basic Usage

Create a `DomainHealthCheck` instance and call the verification methods you need:

```csharp
using DomainDetective;

var healthCheck = new DomainHealthCheck();

// Email security checks
await healthCheck.VerifySPF("example.com");
await healthCheck.VerifyDMARC("example.com");
await healthCheck.VerifyDKIM("example.com", new[] { "default", "selector1" });
await healthCheck.VerifyMX("example.com");

// DNS checks
await healthCheck.VerifyDNSSEC("example.com");
await healthCheck.VerifyNS("example.com");
await healthCheck.VerifySOA("example.com");
await healthCheck.VerifyCAA("example.com");

// Access results
var spf = healthCheck.SpfAnalysis;
var dmarc = healthCheck.DmarcAnalysis;
var mx = healthCheck.MXAnalysis;
```

## Configuring DNS Resolvers

```csharp
using DnsClientX;

var healthCheck = new DomainHealthCheck();
healthCheck.DnsEndpoint = DnsEndpoint.CloudflareWireFormat;

// Or use multiple resolvers
healthCheck.DnsEndpoints.Add(DnsEndpoint.Google);
healthCheck.DnsEndpoints.Add(DnsEndpoint.Quad9);
```

## Comprehensive Check

Run all checks at once:

```csharp
await healthCheck.Verify("example.com");
```

Or specify which checks to run:

```csharp
await healthCheck.Verify("example.com", new[] {
    HealthCheckType.SPF,
    HealthCheckType.DMARC,
    HealthCheckType.DKIM,
    HealthCheckType.MX
});
```

## Working with Results

All analysis results include `Assessments` with structured findings:

```csharp
foreach (var assessment in healthCheck.SpfAnalysis.Assessments) {
    Console.WriteLine($"[{assessment.Level}] {assessment.Title}: {assessment.Description}");
}
```

Assessment levels: `Pass`, `Fail`, `Warning`, `Info`.

## API Reference

See the [full API reference](/api/) for complete documentation of all types and methods.
