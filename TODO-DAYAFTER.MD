# Day-After TODOs — Proposals and Next Steps

This document proposes focused, high‑impact follow‑ups that build on the unified Assessments + Views work. Items are grouped to make implementation modular and testable.

## Guiding Principles
- Prefer precise RFC-aligned checks over heuristic guesswork.
- Keep outputs lossless via views with `Raw`, `Assessments`, `Status/Counts`, and `Recommendations`.
- Scope assessments (Subject) to the most actionable granularity (e.g., host:port for SMTP, RRset for DNS).

## High‑Impact (1–2 days)
- DirectoryExposure enhancement
  - Expand default paths: `.bak`, `~`, `_backup/`, `.DS_Store`, `package-lock.json`, `yarn.lock`, `sitemap.xml`, `sitemap.txt`, `.well-known/security.txt`.
  - New assessments per sensitive file class: `Secrets.DotEnv`, `Backups.Present`, `SourceMap.Exposed`.
- Apex address analysis hardening
  - Tighten PTR hostname normalization (strict trim of trailing dots, lowercase) before forward checks.
  - When overrides are present but analysis is empty, exhaustively hydrate A/AAAA from override and PTR hostnames.
  - Add unit test reproducing Apex_HasAOnly to lock behavior.

## Protocol‑Specific Enhancements
- MX integrity
  - Cross‑NS RRset consistency check (serializable diff of A/AAAA answers per NS).
  - TTL uniformity across MX RRset and their A/AAAA.

- DNSSEC depth
  - NSEC3 Opt‑Out verification when relevant; `Dnssec.Nsec3OptOutRisk`.

- EDNS robustness
  - Warn on UDP fragmentation risk: `Edns.BufferTooLarge` when advertised > 1232 without Path MTU awareness.
  - Track per‑resolver fallback behavior.

- STARTTLS/SMTPTLS grading
  - Add coarse grade (A/B/C/D/F) driven by protocol support, TLS version, key sizes, chain validity, expiry proximity, and hostname match.
  - Assessments for legacy protocols enabled (`SSLv3`, `TLS1.0/1.1`): `Tls.LegacyEnabled`.

- Reverse DNS
  - `Ptr.ForwardMismatch` when PTR→A/AAAA does not map back to original IP.
  - `Ptr.SharedCloudManyToOne` advisory (low severity) to contextualize false positives.

- IP Neighbors
  - Categorize neighbors (e.g., same registrant, disposable domains, high‑risk TLDs) when data available.
  - `MailOnSharedIp` warning when MX or SMTP host is on high co‑tenancy IP.

## WHOIS Enhancements
- Discovery/cache
  - Cache TLD→WHOIS server mapping for the session to reduce repeated lookups.
  - Backoff/retry strategy on transient WHOIS TCP failures (timeout/connect resets).
- Parser coverage
  - Expand locale-specific parser branches (e.g., additional EU ccTLDs); add samples to testdata.

## DNS Resolver Override
- PowerShell parameters
  - DnsEndpoint wired across DNS-backed cmdlets (audit complete); document examples for vendor selection.
  - Validate IPv4/IPv6 endpoints; allow multiple resolvers with first-success semantics (follow-up option on `DnsConfiguration`).
- Defaults and tests
  - Unit tests to verify override is honored and falls back gracefully when unreachable.

## SPF View Enhancements
- Expose key metrics for dashboards
  - Add `RecordLength` to SPF view; ensure `DnsLookupsCount` is present and clearly named.
  - Map warnings/advisories to RFC 7208 (255/512 byte limits, 10-lookup limit, include cycles) in Recommendations.

## DKIM Selector Coverage
- Tests
  - Add DKIM auto-detect tests that probe newly added selectors and assert advisory/key parsing.

## DMARC Aggregate (RUA)
- PowerShell ingestion and summary
  - Unify `Test-DDDmarcAggregate` to use `DmarcReportParser` (v1+v2, xml/gz/zip) and add `-SummarizeBy Ip|HeaderFrom`.
  - Add `RequestedReportingPolicy` computed from `policy_published.fo` and expose in output.
  - Support directory/glob ingestion and optional dedup by report-id and date range.
- CSV/JSON export (cmdlets)
  - Optional `-CsvPath` (and `-Json`) to emit records or summaries for pipelines.

## Scope and Priorities
- Focus first on DomainDetective core + PowerShell cmdlets.
- CLI will reuse cmdlet/core functionality; defer CLI UX improvements to last.

## Views and UX
- Add `Check` → `Area` mapping in views (e.g., Mail/DNS/Web/Security) for grouping in UIs.
- Normalize `Subject` types (domain vs host:port vs URL) across converters consistently; document expectations.
- Add compact “Summary” string in each view (single line) for quick tabular display.

## PowerShell / CLI
- Views by default (completed)
  - All “Test‑*” cmdlets now return views with `Raw` attached. Add a short migration note in module README for users previously consuming raw analysis types.
- Examples/docs
  - Add example scripts in `Docs/REPORTING_USAGE.MD` showing piping views into Select‑Object for quick dashboards.
  - Update examples to reference `view.Raw` where deep data is needed (e.g., chain details already exposed via `-ShowChain`).
  - Document `DnsEndpoint` usage and available resolver presets.

## Testing and Validation
- Snapshot tests for new/updated Converters to verify `Status`, `WarningCount`, `ErrorCount`, and `References` aggregation.
- Integration tests for Subject scoping: confirm per‑server assessments appear under correct `Subject`.
- PowerShell Pester smoke tests: adapt any expectations to `view.Raw` when asserting deep properties.

## Docs and XML Examples
- Extend enum/class XML examples beyond `MailDomainClassificationCategory` (e.g., TLS enums, DnsEndpoint usage).
- Add cmdlet XML `<remarks>` consistently noting “Outputs a view object with full raw analysis attached at Raw”.

## Stretch Ideas
- MT A‑STS deep dive: policy download caching, redirect handling, expiry warnings, `mode=enforce` only when all MX support TLS.
- OCSP stapling and SCT presence checks in TLS flows; add `Tls.OcspMissing` and `Tls.SctMissing` advisories.
- Threat intel scoring: severity weighting by source reputation and recency.
- Passive DNS cache: minimal local cache to reduce rate‑limits and speed up neighbor checks.

---

If you want, I can tackle DirectoryExposure next (sensitive paths + per‑class assessments), followed by EDNS fragmentation risk and Reverse DNS forward‑mismatch — these are high‑value and straightforward to validate.
