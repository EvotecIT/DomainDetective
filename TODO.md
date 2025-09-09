# DomainDetective — Open TODO (Consolidated)

This file consolidates outstanding items from TODO-TOMORROW.MD and TODO-DAYAFTER.MD. Completed entries were removed; items below were validated against the codebase on 2025-09-08.

## High Priority
- Pester: RPKI downgrade (5xx) logged as Warning; pipeline continues; assessment code `RPKI.Query.Failed` present.
- Pester: Word composition headings present (Executive Summary, Overview, All References) and summary table renders; add PS-level test (C# unit test exists).
- Golden report pass (Word): single-domain and multi-domain; verify one-liner intros and References blocks across sections.

## Reports — Word
- Report Settings panel at front (narrative placement, generated timestamp, domain count).
- Per-section narrative intros for all writers (ensure one-liner before Good Posture and Findings consistently across MX/MTA-STS/TLS-RPT/…)
- Tighten recommendation de-duplication in consolidated table.
- DKIM status in summary: derive from worst severity across selectors (Warning/Error/OK), not string max.
- Optional: User-configurable summary column cap (default 4 content columns). CLI/PS surface.

## Reports — HTML
- Parity with Word: add Good Posture for DMARC/DKIM (SPF already done) and align section structure.

## Composition Parity (Next Day)
- Word/HTML ordering polish
  - Verify new ordering controls end-to-end: `-DomainOrder`, `-SectionOrderMode`, `-SectionOrder`.
  - Executive Summary remains canonical; document behavior in README/Module docs.
  - Add verbose trace when `-Verbose` is set: item count, domain count, and per-domain section order.
- HTML parity with Word
  - Add ARC and BIMI HTML section writers; wire into HtmlCompositionReport.
  - Provider Help under ARC/BIMI/MX/SPF/DMARC with topic ordering and badges; include legend line.
  - DKIM selector-count hint and MAILTLS footnote parity (where applicable for HTML).
- Markdown (new)
  - Add MarkdownCompositionReport using OrderingOptions; implement sections: MX, SPF, DKIM, DMARC, DNSBL, Classification, MTA-STS, TLS-RPT.
  - Executive Summary table + per-domain subsections; Good Posture/Findings/References blocks.
  - Hook into PS `Export-DDSecurityReport -ExportFormat Markdown` via ReportDispatcher generator (new IReportGenerator if needed).
- Excel (new)
  - Add ExcelCompositionReport (ClosedXML):
    - Sheet1: Executive Summary (canonical columns; warnings/errors rollup; provider chain line optional).
    - Per-domain sheets in chosen order; per-section tables; auto-fit; basic styling.
  - Hook into PS `Export-DDSecurityReport -ExportFormat Excel` via ReportDispatcher generator (new IReportGenerator if needed).
- PowerShell surface
  - Ensure `Export-DDSecurityReport` help includes ordering params; update examples to demonstrate Input/Custom ordering.
  - Add example scripts for HTML/Markdown/Excel under `Module/Examples` mirroring Word examples.
- Tests
  - Pester: verify ordering (domain and section) for Word/HTML; assert Executive Summary non-empty.
  - Pester: flattening works for piped arrays ($spf,$dmarc,$mx) — domains detected > 0 and sections rendered.
  - xUnit: composition utilities (NormalizeSection, SectionKeyFor) map synonyms correctly.
- Branding controls (optional)
  - `Set-DDExportOptions`: add `-HeaderLogoSizePx`/`-FooterLogoSizePx`; update WordReportCommon to honor.
- Provider docs (dev-only)
  - Provider Docs Verifier task tracked; no public cmdlet.
- Docs
  - README/Module README: ordering options, section canonical order, per-format parity, and examples.

## Competitive Parity (External Feature Gaps)
- DMARC Aggregate (RUA) ingestion and analysis
  - Ingest `.xml`, `.xml.gz`, and `.zip` aggregate reports from a folder and/or mailbox.
  - Parse v1 and v2 formats; normalize into internal JSON snapshots.
  - Rollups: by source IP, by header-from, by result (pass/fail/alignment), and by enforcement mode.
  - Trends: daily/weekly pass rate, top failing sources, alignment gaps; export time series.
  - Reports: Word/HTML sections for Aggregate Reports with posture one‑liners and remediation hints.
- Mail transport security posture
  - MTA‑STS: check TXT record, fetch policy, validate fields (version, mode, max_age, mx). (done)
  - Verify declared MX list matches DNS MX and that MX hosts present STARTTLS with acceptable TLS versions/ciphers. (done)
  - TLS‑RPT: check `_smtp._tls` TXT presence; capture `rua` endpoints and basic sanity of mailto/https URIs. (done)
  - Surface in Good Posture/Findings; include references. (Word done; HTML pending)
- DNSSEC presence and resolver‑based validation
  - Detect DS/DNSKEY presence; attempt AD‑bit verification using multiple resolvers. (done)
  - Summarize as Good Posture tile; include warnings when chain/validation missing. (HTML pending)
- Registration snapshot (WHOIS/RDAP)
  - Query WHOIS (port 43) with server/port override; RDAP fallback when available.
  - Snapshot registrar, creation/update/expiry, domain status codes, nameservers.
  - Compute `DaysUntilExpiration`; warn at configurable thresholds (e.g., <60 days).
  - Track drift across runs (registrar/nameserver changes).
- Resolver override everywhere
  - Expose multi‑resolver lists across CLI/PS; pipe through to DNS layer. (partially done: Test-DDDomainOverallHealth supports -DnsEndpoints, strategy, parallelism)
- Bulk input and CSV export
  - Add `-InputFile` to CLI/PS to process domain lists.
  - Add `-CsvPath` for first‑class CSV export without requiring downstream piping.
- DKIM selector targeting
  - Allow explicit selector list override in addition to enumeration; roll up worst severity across selectors.
- SPF advisories
  - Enforce single‑record rule; flag >255‑char segments; count DNS lookups; hint on `-all` vs `~all` vs `?all`.
## Surpass Moves (Go Beyond Parity)
- RDAP‑first with WHOIS fallback; structured JSON with IANA/IETF status semantics.
- Enforcement readiness scores
  - DMARC: compute readiness to move to `p=reject` (alignment, pass rate trends, authenticated percentage).
  - MTA‑STS/TLS‑RPT: readiness to move to `mode=enforce` (MX coverage, TLS grades, report coverage).
- Portfolio drift detection across runs (registrar, NS, MX, TLS posture) with concise diff in reports.
- MX TLS coverage matrix per domain (each MX host: STARTTLS, min TLS version, cert validity, SNI behavior) summarized in Word/HTML.
- PS/CLI: `-Server` multi‑resolver strategies exposed (FirstSuccess/FastestWins/SequentialAll) with timeouts and IPv6 preference.
- HTML report polish: sticky TOC, anchors, and expandable “+N more” lists consistent with Word summary behavior.

## CLI / PowerShell
- CLI: expose company branding options (CompanyName/Address/Year/Logo/Header/Watermark) and pass to composition.
- PS: `-ShowPositives` switch for table views to list posture signals quickly.
- Posture one-liner: CLI `--posture`, PS `-Posture` to emit condensed controls line and JSON variant.
- Wizard: HTML export parity (reuse posture panels).
- Persona: optional concise mode (cap line length per stage).

## Networking / Resolvers
- DNS Resolver Override (PS + Core)
  - Integrate DnsClientX multi‑resolver in `DnsConfiguration`. (done)
    - FirstSuccess/FastestWins/SequentialAll strategies. (done)
    - MaxParallelism support. (done)
    - Accept resolver list as `DnsEndpoint[]`. (done)
    - String parsing of resolver URIs. (skipped – not needed)
    - Batch API preserving order. (pending)
  - Endpoint validation and toggles
    - Friendly errors for invalid endpoints. (pending)
    - Global per‑query/per‑endpoint timeouts. (pending)
    - TTL passthrough surfaced where useful. (pending)
  - PowerShell/CLI surface
    - Overall health cmdlet supports `-DnsEndpoints`, strategy, parallelism. (done)
    - Extend to other testing cmdlets. (pending)
  - Tests
    - Unit tests for multi‑resolver behavior. (pending)
  - Docs
    - Examples in README and Examples project. (done)

## Providers / Positives
- Add Info-level positives where meaningful:
  - DNSSEC: DS present/chain valid.
  - NS: diverse authoritative NS (AS/vendor diversity).
  - RPKI: “all ROAs valid” per domain rollup (RPKI per-IP positives exist).

## Tests & QA
- Snapshot tests for Views: verify Recommendations exclude Info; Positives include only Info (autodiscover/subject policies/etc.).
- DKIM: auto-detect tests for new selectors (assert advisory/key parsing).
- Integration tests: assessments stamped with correct Subject scopes (e.g., per-server).
- Pester smoke: adapt deep asserts to view.Raw across cmdlets.
- xUnit: MTA‑STS ↔ MX TLS correlation (modern/missing/weak). (done)
- xUnit: DNSSEC multi‑resolver AD‑bit info code. (done)

## Docs & Examples
- Document the narrative metadata contract so PS/CLI and Word/HTML remain in sync.
- Update examples for company branding, Good Posture sections, and dynamic Executive Summary behavior.
- Extend XML examples for enums/classes (TLS enums, DnsEndpoint usage). (done)
- Cmdlet XML remarks: outputs a view object with `.Raw` and `.Narrative` when available.
- Add dashboard usage examples showing `Select-Object` over views and `.Raw` for deep data.
- Add README + .ps1 examples for multi-resolver (C#/PowerShell). (done)

## Internal Tooling (Optional)
- Provider Docs Verifier (dev-only)
  - Walk `ProviderRegistry.All` → `p.Docs` topics; skip `Url = null`.
  - Check only on a whitelist of vendor domains; third‑party links are warnings.
  - Age gate: recheck when `LastVerified` older than 180 days.
  - HEAD with fallback GET; allow ≤3 redirects; accept 2xx/3xx; flag 4xx/5xx.
  - Capture final same‑domain redirect as suggested replacement; cross‑domain redirects are flagged only.
  - Output single JSON artifact + short console summary; no user‑facing cmdlet.
  - Optional CI (weekly) to upload artifact and open an issue on repeated failures; never runs during end‑user commands.

## PowerShell Output Conventions
- DomainOverallHealth: return View with `.Raw` (done; `-Raw`/`-Summary` removed).
- Convert remaining Test-* cmdlets to View outputs exposing `.Raw`.
- Ensure exports run after pipeline output across cmdlets.

## Reporting (Consolidated Roadmap)
- Narratives in core for all areas; views surface `.Narrative`.
- Word (OfficeIMO): cover, TOC, numbered headings, header/footer branding, watermark, styled tables; charts later.
- HTML (HtmlForgeX): anchors + sticky TOC, info cards, provider summaries, explainers; charts later.
- Multi-domain aggregate: portfolio matrix + per-domain sections.

## Synthetic Monitoring (Future)
- Uptime checks: scheduled HTTP(S) probe with TLS posture + header checks; trend charts and alert thresholds. Easy
- Latency metrics: TTFB/total per probe; regional vantage points; aggregation. Medium
- Waterfall charts: generate from static scan (HEAD/GET timings) for first-load; store snapshots. Medium
- Alerts/integrations: webhook/Slack/email; certificate expiry warnings (reuse CertificateMonitor). Medium
- Transaction flows (multi-step): optional browser required; model steps, assertions, data entry. Hard
