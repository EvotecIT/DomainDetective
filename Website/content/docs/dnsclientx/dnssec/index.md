---
title: DNSSEC and resolution
description: Validate DNSSEC locally with DnsClientX, read Secure, Insecure, Bogus and Indeterminate results, resolve iteratively from the root with QNAME minimisation and manage root trust anchors.
slug: dnssec
collection: docs
layout: docs
---

DnsClientX validates DNSSEC itself. A resolver's AD flag tells you what that resolver believes; local validation builds and verifies the chain to a configured root trust anchor on your machine.

## Validate a response

```csharp
using DnsClientX;

using var client = new ClientX(DnsEndpoint.Cloudflare);
var response = await client.Resolve("evotec.pl", DnsRecordType.A,
    requestDnsSec: true,
    validateDnsSec: true);

Console.WriteLine($"Resolver AD flag: {response.AuthenticData}");
Console.WriteLine($"Local validation: {response.DnsSecValidationStatus}");
Console.WriteLine(response.DnsSecValidationMessage);
```

| Status | Meaning |
| --- | --- |
| `Secure` | DnsClientX built and verified a chain to a configured root trust anchor. |
| `Insecure` | A secure parent authenticated an unsigned delegation. |
| `Bogus` | A cryptographic or proof failure. |
| `Indeterminate` | The response, trust state or supported algorithms were not enough to decide. |

Authenticated denial is checked through NSEC and NSEC3 proofs with delegation-cut awareness. A compact-denial answer is reported as NXDOMAIN through `EffectiveStatus` only when a locally verified proof and a secure chain support it.

## Algorithms

The dependency-free validator supports RSA/SHA-1 (algorithms 5 and 7, for compatibility), RSA/SHA-256 and RSA/SHA-512 on every target, plus ECDSA P-256 and P-384 on .NET 8 and .NET 10. Ed25519 and Ed448, and ECDSA on older targets, come from the optional `DnsClientX.DnsSec.EdDsa` package, which you enable explicitly per client.

## Resolve from the root

The `RootServer` profile resolves iteratively instead of asking a recursive resolver. It applies RFC 9156 QNAME minimisation by default, asking for one label at a time so intermediate servers never see the full name, and reports how many minimised queries and fallbacks it used.

```csharp
using var root = new ClientX(DnsEndpoint.RootServer);
var response = await root.Resolve("evotec.pl", DnsRecordType.A, requestDnsSec: true, validateDnsSec: true);
Console.WriteLine($"{response.QNameMinimizedQueryCount} minimised queries");
```

## Trust anchors

The IANA root trust anchors are bundled. RFC 5011 automated rollover is opt-in because durable state belongs to your application: give DnsClientX a private, durable file and schedule explicit refreshes. Zone-qualified DS anchors can bind validation for private zones.

## In DomainDetective

DomainDetective's DNSSEC and DANE checks use this validator, which is why their results distinguish a failed TLSA query from a secure absence.

## Next steps

- [Zones and updates](/docs/dnsclientx/zones/)
- [Run the DNSSEC check](/tools/dnssec/)
