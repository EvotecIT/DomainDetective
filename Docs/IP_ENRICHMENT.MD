# IP Enrichment (Discovery / Inventory)

## What this check does

The IP Enrichment check enumerates IP addresses discovered for a domain and enriches them with:

- Reverse DNS (PTR) hostnames
- RDAP network hints (CIDR/prefix, country, org/ASN best-effort)
- Offline GeoIP hints (country/region when available)

This helps you understand the hosting footprint (ASNs/countries), spot unexpected networks, and quickly review reverse DNS hygiene.

## Inputs

By default the check gathers IPs from:

- Apex `A` / `AAAA`
- MX host `A` / `AAAA` (bounded by `MaxHostsPerKind`)
- NS host `A` / `AAAA` (bounded by `MaxHostsPerKind`)

Optional additional IPs can also be provided programmatically.

## Data captured

- Query status: success/failure + reason (when available)
- Counts:
  - unique IPs enriched
  - total rows (includes per-source duplicates)
  - distinct ASN count (best-effort)
  - distinct country count (best-effort)
  - top ASN / top country summaries
- Rows (typed):
  - IP, address family, source kind + host
  - PTR / PTR records
  - ASN / AS name (best-effort)
  - CIDR/prefix
  - country/region hints

## Controls / tuning

The primary implementation lives in `DomainDetective.IpEnrichmentAnalysis`.

- `IncludeMxHostAddresses` / `IncludeNsHostAddresses`
- `MaxHostsPerKind` (default: `20`)
- `MaxUniqueIpsToEnrich` (default: `200`)
- `MaxParallelism` (default: `8`)

When a cap is hit, `ResultsCapped` is set and an informational assessment is emitted.

## Output surfaces

- HTML report: “IP Enrichment” section (summary + findings + ASN/country counts + enriched row table + references)
- Word report: “IP Enrichment” section (summary + evidence tables + findings)
- Excel report (net8.0): “IP Enrichment” block (summary + ASN/country counts + rows)

## Notes and limitations

- RDAP metadata varies by registry; ASN/org extraction is best-effort.
- Reverse DNS is informational; many IPs legitimately do not have PTR records.
- GeoIP hints are offline and may be incomplete depending on the embedded database.

