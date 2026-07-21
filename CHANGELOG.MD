## Unreleased

### DNS reliability and shared ownership
- Centralized provider selection, concurrency, retries, response filtering, local DNSSEC validation, AXFR, and diagnostic wire queries on DnsClientX 2.0
- Removed DomainDetective's duplicate multi-resolver, DNSSEC cryptography, and production UDP/TCP DNS implementations
- Preserved full response metadata when filtering records and propagated cancellation through DNS operations
- Stopped treating recursive-resolver fallback data as authoritative-server evidence in DNS health checks
- Stopped combining AD claims from unrelated resolvers or treating a signed parent as proof for a private/unsigned child; DNSSEC summaries now use DnsClientX's local validation status
- Reuse and safely dispose shared resolver clients, including operation-scoped DNSSEC resolvers and concurrent configuration replacement without terminating in-flight queries
- Keep standalone DNSSEC validation on the system or caller-configured resolver instead of silently sending names to an implicit public fallback list
- Added IPv6-aware authoritative probes, bounded shared concurrency, RFC-hardened AXFR validation, and reusable CHAOS/EDNS diagnostic queries
- Corrected browser DoH response-code mapping for DnsClientX extended RCODEs and moved website tests to the supported, non-vulnerable bUnit package
- `MultiResolverStrategy` now comes directly from the DnsClientX namespace; `SequentialAll` is renamed to `SequentialFallback`

## 1.0.0

### What's Changed
- Initial release of Domain Detective
- Includes CLI and PowerShell module
- Supports checks for SPF, DMARC, DKIM, CAA, NS, SOA, DNSSEC and DANE/TLSA records

## 1.0.1

### What's Changed
- Enabled trimming on CLI and example projects with partial mode to align with .NET 8 NativeAOT guidance

## 1.0.2

### What's Changed
- Added TTL analysis for common DNS record types
- New `Test-DnsTtl` PowerShell cmdlet

## 1.0.3

### What's Changed
- DNSSEC validation now walks the delegation chain and checks DS records
- DNSSEC analysis summarizes any mismatches for each chain element

## 1.0.4

### What's Changed
- SOA analysis now validates serial number format and suggests using `YYYYMMDDnn`
  when an invalid pattern is detected

## 1.0.5

### What's Changed
- Evaluate Strict-Transport-Security header for preload readiness
- Added property to report if the `preload` token is present
- Added tests for headers from hstspreload.org
