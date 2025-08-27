# DomainDetective — Restart Checklist

Use this checklist to pick up work quickly. Mark items as you go.

## Quick Start
- [ ] Pull latest + open repo (ensure correct SDK installed).
- [ ] Build solution for all TFMs (`dotnet build`); fix any red.
- [ ] Run a couple sample checks (SPF/DKIM/HTTP) and verify `Assessments` + `Recommendations` are present on returned objects.
- [ ] Skim console/PS logs for unexpected uncoded messages.
- [ ] Commit small, focused changes frequently.

## Core Recommendations System
- [x] Centralize `RecommendationCatalog` with modular providers per domain area.
- [x] Expose `RecommendationEngine` for grouping and uniqueness.
- [x] Add `Recommendations` to analyses implementing `IHasAssessments`.
- [x] Enrich `RecommendationAdvice` with `Impact`, `Effort`, `Verify`, `Domain`, `Tags`.
- [ ] Finish wiring remaining analyses to `IHasAssessments` + `Recommendations` (and add collectors):
  - [ ] `NSAnalysis`
  - [ ] `SOAAnalysis`
  - [ ] `RobotsTxtAnalysis`
  - [ ] `AutodiscoverAnalysis` (DNS)
  - [ ] `WhoisAnalysis`
  - [ ] `RdapAnalysis`
  - [ ] `ZoneTransferAnalysis`
  - [ ] `DnsTunnelingAnalysis`
  - [ ] `OpenResolverAnalysis`
  - [ ] `DNSBLAnalysis` (block lists)
  - [ ] `IPNeighborAnalysis` (now emits coded logs; add IHasAssessments+Recommendations)

## Providers (Advice Content)
- [x] HTTP (HSTS/CSP/Mixed content/HPKP, common missing headers)
- [x] SPF (lookups > 10, include cycles, size/chunks/macros)
- [x] DMARC (alignment, URIs, reporting)
- [x] DNSSEC (expiring RRSIG, DS issues)
- [x] STARTTLS / SMTP AUTH (EHLO, 8BITMIME)
- [x] BIMI (https, mime, size/attrs/dimensions)
- [x] SMIMEA (host/usage/selector, missing records)
- [x] CAA (flags, unknown critical tag, duplicates)
- [x] CNAME (takeover risk, dangling targets)
- [x] security.txt (contact, canonical https, PGP verify)
- [x] Directory exposure (exposed listing)
- [ ] Add providers for:
  - [ ] WHOIS (query failure, parsing anomalies)
  - [ ] RDAP (request failure, status handling)
  - [ ] Open Relay (check failed)
  - [ ] DNSBL (listed, query failures by provider)
  - [ ] Autodiscover DNS (missing/invalid SRV/CNAME, misroutes)
  - [ ] NS/SOA (misconfig, serial skew, MNAME/RNAME format, refresh/retry extremes)
  - [ ] IP Neighboring (passive DNS failures, high-risk neighbors if defined)

## HTTP Fine-Grained Coverage
- [x] Emit HSTS missing/short/unknown directive codes
- [x] Emit CSP unsafe directives code
- [x] Emit mixed-content code
- [x] Emit deprecated headers (X-XSS-Protection, Expect-CT)
- [x] Emit missing security header codes (CSP, Referrer-Policy, X-CTO, COOP/COEP/CORP, OAC, X-Permitted-…)
- [ ] Expand advice with examples/snippets for common frameworks (nginx/Apache/Cloudflare) in `How`
- [ ] Add checks for header value quality (e.g., `X-Frame-Options` DENY/SAMEORIGIN; Permissions-Policy parsing quality)

## Persona & UX
- [x] `AssessmentNarrator` uses catalog titles; `NarrateDetailed` adds short Why.
- [ ] CLI wizard: for each section (SPF/DKIM/HTTP…), show `analysis.Recommendations` immediately below the main facts.
- [ ] Optional CLI flags: `--persona-live`, `--persona-verbose` to mirror persona narration during checks.
- [ ] PowerShell: ensure returned objects already have `Assessments` + `Recommendations` (no extra cmdlets needed). Add examples to docs.

## Reports
- [ ] HTML report: add Recommendations section using `hc.RecommendationViews` (Title, Why, How, Impact, Effort, Verify, Links).
- [ ] (Optional) Word/Excel exporters: same data model; reuse views where possible.
- [ ] Add category grouping (Impersonation/Privacy/Branding/Infrastructure) driven by `RecommendationDomain`.

## Localization & Data Quality
- [ ] Plan i18n: externalize provider strings to resources; keep codes stable.
- [ ] Fill `Impact/Effort/Verify` for all providers (consistency pass).
- [ ] Add `Priority` (derived from Severity + Impact) for UI ordering.

## Testing & Tooling
- [ ] Build all TFMs (`net8.0` etc.) and fix any remaining compile errors.
- [ ] Add unit tests for code→advice mapping (snapshot or table-driven).
- [ ] Add tests ensuring `Recommendations` non-empty for typical misconfig inputs per protocol.
- [ ] Add lints for adding new Codes + Providers (contrib guidelines).

## Docs
- [ ] Document the Codes scheme and how to add new codes/providers.
- [ ] Document how `Assessments` and `Recommendations` appear on objects (C#, PS examples).
- [ ] Update persona docs to show `NarrateDetailed` usage and flags.

## Stretch Goals
- [ ] Scoring: add per-recommendation weights; compute top-N critical actions in reports.
- [ ] Exporters: `--export-recommendations json|yaml` for CLI; PS param to export cleanly.
- [ ] Telemetry-free offline mode examples (no external calls) for demos/tests.

---

Notes
- All new advice should be added via a provider under `Diagnostics/Recommendations/` with stable Codes.
- Prefer authoritative links (MDN/IETF/vendor) and keep `How` vendor-neutral with safe defaults.
- Keep analysis classes lean; surface findings via logger → AssessmentCollector → Assessments → Recommendations.
