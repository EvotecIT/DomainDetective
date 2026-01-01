# DNS Inventory

## What this check does

The DNS Inventory check queries a small set of common DNS record types for a domain apex and captures:

- Records returned in the Answer section (always)
- Records returned in the Authority section (optional)
- Records returned in the Additional section (optional)
- TTL values for all captured records

This is designed for discovery and troubleshooting: quickly see what a domain exposes via DNS without running all specialized checks.

## Record types queried

Default record types:

- `A`
- `AAAA`
- `CNAME`
- `MX`
- `NS`
- `SOA`
- `TXT`
- `CAA`

## Controls / tuning

The primary implementation lives in `DomainDetective.DnsInventoryAnalysis`.

- Provider / technology inference (best-effort, deterministic, no extra lookups)
  - `Provider` / `ProviderEvidence` are derived from NS/SOA patterns.
  - `MailProvider` / `MailProviderEvidence` are derived from MX host patterns.
  - `CnameTargetProvider` / `CnameTargetFlags` / `CnameTargetEvidence` are derived from the apex CNAME target.
  - `TxtSignals` / `TxtSignalsEvidence` are derived from TXT strings (e.g., SPF + common verification tokens).
  - `CaaIssuers` / `CaaIssuersEvidence` are derived from CAA `issue*` values.

- `IncludeAuthorities` (default: `true`)
- `IncludeAdditional` (default: `false`)
- `MaxRecordsPerSection` (default: `200`)
- `QueryConcurrency` (default: `4`)
- `QueryOverride` (test/offline hook returning a `DnsClientX.DnsResponse`)

DNS queries use `DomainDetective.DnsConfiguration` and can be influenced via:

- `DnsConfiguration.DnsEndpoint` / `DnsConfiguration.DnsSelectionStrategy`
- `DnsConfiguration.DnsEndpoints` + `DnsConfiguration.MultiResolverStrategy`

## Output surfaces

- HTML report: “DNS Inventory” section with summary, inference evidence, query results, and captured record sample table.
- Word report: “DNS Inventory” section with summary, inference evidence, query results, and captured record sample table.
- Excel report (net8.0): “DNS Inventory” block with summary, inference evidence, query results, and record sample table.

## Notes and limitations

- This is an inventory view, not a validation of policy correctness (those live in dedicated checks like SPF/DMARC/DNSSEC).
- Large zones can return a lot of data; capture is bounded by `MaxRecordsPerSection` and report renderers may further cap rows.
