---
title: Zones and updates
description: Transfer DNS zones with AXFR, IXFR and XFR-over-TLS, check ZONEMD digests, authenticate with TSIG, parse zone files and send atomic RFC 2136 updates with DnsClientX.
slug: zones
collection: docs
layout: docs
---

DnsClientX can read and change zones on servers you are authorised to use. Transfers and updates go over TCP (or TLS) to an explicit authoritative server; built-in public profiles are rejected for updates.

## Zone transfers

```csharp
using DnsClientX;

using var client = new ClientX("192.0.2.53", DnsRequestFormat.DnsOverTCP);

// Full transfer (AXFR)
var zone = await client.ZoneTransferAsync("example.com");

// Streaming transfer, chunk by chunk
await foreach (var rrset in client.ZoneTransferStreamAsync("example.com")) {
    Console.WriteLine(string.Join(", ", rrset));
}

// Incremental transfer (IXFR) from a known serial
var changes = await client.IncrementalZoneTransferAsync("example.com", currentSerial: 2026072100);
```

Transfers validate the opening and closing SOA records and response correlation. RFC 9103 XFR-over-TLS protects the transfer in transit, and RFC 8976 ZONEMD digests let you check that the zone you received is the zone that was signed.

```powershell
Get-DnsZone -Zone example.com -Server 192.0.2.53
```

## TSIG

Configure a `TsigKey` and DnsClientX signs requests and requires a valid, chained TSIG on every response message, including multi-message transfers.

## Zone files

A diagnostic BIND master-file parser reads `$ORIGIN`, `$INCLUDE`, `$GENERATE`, owner inheritance, multi-line records and RFC 3597 generic types.

## Dynamic updates (RFC 2136)

```csharp
var configuration = new Configuration("192.0.2.53", DnsRequestFormat.DnsOverTCP) {
    TsigKey = TsigKey.FromBase64("update-key.example.com", secretFromSecureStorage)
};
using var updater = new ClientX(configuration);

await updater.UpdateRecordAsync("example.com", "www.example.com", DnsRecordType.A, "192.0.2.1", ttl: 300);

// All or nothing: both records, only if the name is still absent
var batch = new DnsUpdateBatch("example.com", new[] {
    DnsUpdateOperation.Add("api.example.com", DnsRecordType.A, "192.0.2.20", ttl: 300),
    DnsUpdateOperation.Add("api.example.com", DnsRecordType.TXT, "role=api", ttl: 300)
}, new[] { DnsUpdatePrerequisite.NameAbsent("api.example.com") });
await updater.UpdateRecordsAsync(batch);
```

A batch is one RFC 2136 message: the server checks every prerequisite before applying any change, and a failed prerequisite leaves the zone untouched. `Invoke-DnsUpdate` asks for confirmation before it sends anything.

## Next steps

- [Service discovery](/docs/dnsclientx/discovery/)
- [.NET API reference](/api/dnsclientx/)
