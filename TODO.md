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

## CLI / PowerShell
- CLI: expose company branding options (CompanyName/Address/Year/Logo/Header/Watermark) and pass to composition.
- PS: `-ShowPositives` switch for table views to list posture signals quickly.
- Posture one-liner: CLI `--posture`, PS `-Posture` to emit condensed controls line and JSON variant.
- Wizard: HTML export parity (reuse posture panels).
- Persona: optional concise mode (cap line length per stage).

## Networking / Resolvers
- DNS Resolver Override (PS + Core)
  - Integrate DnsClientX multi‑resolver APIs in `DnsConfiguration`.
    - Wire `IDnsMultiResolver` (FirstSuccess as default) for `QueryDNS`/`QueryFullDNS`.
    - Support `MultiResolverOptions` (Strategy: FirstSuccess|FastestWins|SequentialAll; MaxParallelism; PreferIPv6; AllowTcpFallback).
    - Accept resolver list as `DnsResolverEndpoint[]` and parse strings: `1.1.1.1:53`, `[2606:4700:4700::1111]:53`, `dns.google:53`, `https://dns.google/dns-query`.
    - Adopt `QueryBatchAsync` for batch lookups while preserving input order.
  - Endpoint validation and toggles
    - Validate IPv4/IPv6 endpoints; friendly errors when invalid/blocked.
    - Global per‑query timeout + per‑endpoint timeout; propagate cancellation tokens.
    - TTL passthrough (min/avg) when available on responses (surface on views where useful).
  - Tests
    - Override honored; graceful fallback on unreachable resolvers.
    - IPv6‑only and IPv4‑only scenarios; mixed family selection.
    - Batch preserves order and isolates failures.
  - Docs
    - Vendor preset examples (Cloudflare/Google/Quad9/DoH) and resolver string formats.
    - Strategy guidance (FirstSuccess vs FastestWins vs SequentialAll).

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

## Docs & Examples
- Document the narrative metadata contract so PS/CLI and Word/HTML remain in sync.
- Update examples for company branding, Good Posture sections, and dynamic Executive Summary behavior.
- Extend XML examples for enums/classes (TLS enums, DnsEndpoint usage, resolver strings).
- Cmdlet XML remarks: outputs a view object with `.Raw` and `.Narrative` when available.
- Add dashboard usage examples showing `Select-Object` over views and `.Raw` for deep data.

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

---

Validation notes (done elsewhere, removed here)
- Word Executive Summary intro paragraph — present.
- Executive Summary is dynamic: controls list and columns reflect requested checks; visual hint for omitted columns.
- Word: page breaks between domains; TOC headings per domain — present.
- DNSBL Word: standardized section with Summary/Good posture/Findings/Evidence/References — present.
- Positives emitted for DMARC (rua/ruf, strict alignment, pct=100) and DKIM (sha256, canonicalization valid, key type valid) — present.
- Mail TLS view enrichments (Issuer/ValidFrom/ValidTo/Thumbprint) — present in view objects.
- RPKI external failures downgraded to Warning — present (C# test added).
