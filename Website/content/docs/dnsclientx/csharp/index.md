---
title: DnsClientX for .NET
description: Query DNS from C# with direct client usage, static helpers, typed answers, multi-resolver workflows, and EDNS options.
slug: csharp
collection: docs
layout: docs
---

## Direct Query

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Cloudflare);
DnsResponse response = await client.Resolve("evotec.pl", DnsRecordType.A);

foreach (var answer in response.Answers) {
    Console.WriteLine($"{answer.Type}: {answer.Data}");
}
```

## Static Helper

```csharp
using DnsClientX;

DnsResponse response = await ClientX.QueryDns("evotec.pl", DnsRecordType.MX, DnsEndpoint.Google);

foreach (var answer in response.Answers) {
    Console.WriteLine($"{answer.Type}: {answer.Data}");
}
```

## Typed Records

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Cloudflare);
DnsResponse response = await client.Resolve("google.com", DnsRecordType.MX, typedRecords: true);

foreach (var answer in response.TypedAnswers ?? Array.Empty<object>()) {
    Console.WriteLine(answer.GetType().Name);
}
```

## Builder With EDNS Client Subnet

```csharp
using DnsClientX;

using var client = new ClientXBuilder()
    .WithEndpoint(DnsEndpoint.Google)
    .WithEdnsOptions(new EdnsOptions {
        EnableEdns = true,
        Subnet = new EdnsClientSubnetOption("203.0.113.0/24")
    })
    .Build();

DnsResponse response = await client.Resolve(
    "evotec.pl",
    DnsRecordType.A,
    requestDnsSec: true,
    validateDnsSec: false);
```

## Need Signatures, Namespaces, Or Source Links?

Use the generated [DnsClientX .NET API reference](/api/dnsclientx/) when you want exact member signatures, XML summaries, and source-linked documentation.
