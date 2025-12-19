# DomainDetective — Open TODO (Consolidated)

This file consolidates outstanding items from TODO-TOMORROW.MD and TODO-DAYAFTER.MD. Completed entries were removed; items below were validated against the codebase on 2025-12-19.

## High Priority
- Golden report pass (Word): single-domain and multi-domain; verify one-liner intros and References blocks across sections.

## Reports — Word
- Optional: CLI surface for summary column cap (default 4 content columns). PS is wired via `Set-DDExportOptions -SummaryColumnCap`.

## Composition Parity (Next Day)
- Word/HTML ordering polish
  - Verify new ordering controls end-to-end: `-DomainOrder`, `-SectionOrderMode`, `-SectionOrder`.
  - Executive Summary remains canonical; document behavior in README/Module docs.
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
  - Surface in HTML Good Posture/Findings; include references.
- DNSSEC presence and resolver‑based validation
  - Summarize as Good Posture tile in HTML; include warnings when chain/validation missing.
- Registration snapshot (WHOIS/RDAP)
  - Query WHOIS (port 43) with server/port override; RDAP fallback when available.
  - Snapshot registrar, creation/update/expiry, domain status codes, nameservers.
  - Compute `DaysUntilExpiration`; warn at configurable thresholds (e.g., <60 days).
  - Track drift across runs (registrar/nameserver changes).
- Resolver override everywhere
  - Expose multi‑resolver lists across CLI/PS beyond Test-DDDomainOverallHealth; pipe through to DNS layer.
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
  - Batch API preserving order. (pending)
  - Endpoint validation and toggles
    - Friendly errors for invalid endpoints. (pending)
    - Global per‑query/per‑endpoint timeouts. (pending)
    - TTL passthrough surfaced where useful. (pending)
  - PowerShell/CLI surface
    - Extend to other testing cmdlets. (pending)
  - Tests
    - Unit tests for multi‑resolver behavior. (pending)

## Tests & QA
- Snapshot tests for Views: verify Recommendations exclude Info; Positives include only Info (autodiscover/subject policies/etc.).
- DKIM: auto-detect tests for new selectors (assert advisory/key parsing).
- Integration tests: assessments stamped with correct Subject scopes (e.g., per-server).
- Pester smoke: adapt deep asserts to view.Raw across cmdlets.

## Docs & Examples
- Document the narrative metadata contract so PS/CLI and Word/HTML remain in sync.
- Update examples for company branding, Good Posture sections, and dynamic Executive Summary behavior.
- Cmdlet XML remarks: outputs a view object with `.Raw` and `.Narrative` when available.
- Add dashboard usage examples showing `Select-Object` over views and `.Raw` for deep data.

## Internal Tooling (Optional)
- Provider Docs Verifier (dev-only)
  - Walk `ProviderRegistry.All` → `p.Docs` topics; skip `Url = null`.
  - Check only on a whitelist of vendor domains; third‑party links are warnings.
  - Age gate: recheck when `LastVerified` older than 180 days.
  - HEAD with fallback GET; allow ≤3 redirects; accept 2xx/3xx; flag 4xx/5xx.
  - Capture final same‑domain redirect as suggested replacement; cross‑domain redirects are flagged only.
  - Output single JSON artifact + short console summary; no user‑facing cmdlet.
  - Optional CI (weekly) to upload artifact and open an issue on repeated failures; never runs during end‑user commands.

## Reporting (Consolidated Roadmap)
- Narratives in core for all areas; views surface `.Narrative`.
- Word (OfficeIMO): cover, TOC, numbered headings, header/footer branding, watermark, styled tables; charts later.
- HTML (HtmlForgeX): anchors + sticky TOC, info cards, provider summaries, explainers; charts later.
- Multi-domain aggregate: portfolio matrix + per-domain sections.

## Composition Unification — End-to-End Checklist (Added 2025-09-14)
- Shared Data Model (SectionProjectors)
  - Keep DTO surface minimal and consistent: Summary (KV), Positives, Findings (non‑Info), References (+ Rows where applicable e.g., DKIM selectors). [ongoing refinement]

- Word
  - Remove legacy view‑only code paths once HTML/Markdown/Excel parity is validated. [pending]
  - Add a one‑shot “parity mode” toggle (internal) to compare DTO vs. legacy output counts (Findings/Positives/References) for test runs. [pending]

- Excel
  - Switch per‑section panes to DTOs (Transport: MTA‑STS/TLS‑RPT; DNS: NS/SOA/DNSSEC; Security: CAA/DANE/RPKI; Reputation: DNSBL; Auth: SPF/DKIM/DMARC). [pending]
  - Preserve evidence tables where useful (RPKI, Zone Transfer). [pending]
  - Honor `ExcelProfile` (Workbook|Dashboard) across panes with shared DTOs (content pending).

- PowerShell/CLI Surface
  - Update Get‑Help and README usage examples for profiles, inline `ScriptBlock` composition, and the MarkdownHtml rename. [pending]

- Tests & Parity
  - Pester: Validate that Word/HTML/Markdown/Excel share consistent per‑section counts (Findings/Positives/References) for a known domain set. [pending]
  - In‑memory parity assertions with a readable diff printed to test output on mismatch (no CSV/JSON files). [pending]
  - Pester: Verify `Export-DDSecurityReport` `-HtmlProfile`/`-ExcelProfile` wiring and that outputs differ as expected. [pending]

- Docs & Samples
  - README: “Single Composition Layer” section describing CompositionBuilder + SectionProjectors and how all formats consume it. [pending]
  - Update examples for HTML/Markdown/Excel parity; add before/after screenshots for Dashboard vs Document profiles. [pending]
  - Module help: add profile parameters, inline block examples, and notes on evidence tables retained per format. [pending]

- Clean‑up
  - After parity green: remove deprecated view‑only rendering branches in HTML/Markdown/Excel and any unused helpers. [pending]
  - Reduce nullable warnings in migrated code paths (target: zero warnings in Reports.*). [pending]
  - Tighten provider‑help rendering null‑checks (Word/HTML). [pending]

Acceptance Criteria (for closing unification)
- For a curated domain set, all four formats show matching per‑section status strings and Findings/Positives/References counts (± UI differences) sourced from SectionProjectors.
- Profiles switch presentation only; underlying data remains identical.
- Legacy code paths removed or guarded behind dev‑only flags; CI parity tests pass.

### Unified Document + Dashboard Profiles (2025-09-15)

- Canonical Structure (Document profile)
  - Apply the same top‑to‑bottom outline for Word, Markdown, MarkdownHtml: Cover/Front‑Matter (as applicable), TOC, Executive Summary, Legend, Mail Providers, Per‑Domain sections (Overview → per‑section blocks), References. [pending]
  - Normalize heading levels: H1/H2/H3 mapping consistent across all three; verify TOC min/max levels. [pending]
  - Executive Summary table columns canonicalized: Domain | MX | SPF | DKIM | DMARC | MTA‑STS | TLS‑RPT | Classification | Findings (W/E). Share builder across formats. [pending]
  - Severity mapping canonicalized: Error > Warning > OK; DKIM roll‑up is max severity across selectors. Shared util used by all formats. [pending]
  - Provider chain line (Primary; Gateways; Outbound) and top provider links rendered with the same data contract. [pending]

- Dashboard Structure (HTML/Excel profiles)
  - HTML (HtmlForgeX) uses Dashboard profile for KPIs + Summary grid inspired by Projects/HtmlForgeX/HtmlForgeX.Examples/Reports/DomainComplianceReport.cs; wire to CompositionBuilder + SectionProjectors (no fake data). [pending]
  - Excel uses Workbook (document) and Dashboard profiles; Dashboard mirrors HTML KPIs + compact summary; Workbook mirrors Word/Markdown per‑domain sheets. Base all visuals on the same DTOs. [pending]
  - Add Demo snapshots (PNG) regenerated from new HTML Dashboard + Excel Dashboard to Demo/ for parity gallery. [pending]

- Shared Data Contract (ReportSchema v1)
  - Introduce a small immutable schema for top‑level composition: ReportHeader (Title, GeneratedOn, SubjectCount, Profiles), ExecutiveSummaryRow, ProviderChain, and PerDomain (Overview, Sections[]). [pending]
  - Add StatusPalette service (text → status category) used by HTML/Excel conditional visuals and by emoji status in Markdown. [pending]

- Output Adapters
  - Word: ensure all section writers accept projector DTOs; remove legacy view‑only branches after parity green. [pending]
  - HTML (HtmlForgeX): create Dashboard composer that maps ExecutiveSummaryRow to KPI cards + summary Tabler table; retain optional Document profile that renders per‑domain accordions. [pending]

- Ordering & TOC
  - Single source of truth for CanonicalSectionOrder used by all renderers; respect `-SectionOrderMode` and `-SectionOrder`. [pending]
  - Ensure TOC/anchors exist and match headings for Word (built‑in TOC), Markdown (generated ToC), HTML (Tabler anchors). [pending]

- Tests (Parity Pack)
  - Add “Parity Fixtures” test that runs the same domain set through Word, Markdown, MarkdownHtml, HTML‑Document, HTML‑Dashboard, Excel‑Workbook, Excel‑Dashboard and compares in memory (domain, section, status, warnings, errors). On failure, print a short diff to the test output. [pending]
  - Pester: validate Mail Providers (Primary/Gateways/Outbound) string equality across formats. [pending]
  - xUnit: ExecutiveSummaryBuilder computes identical totals for W/E across formats; DKIM roll‑up obeys worst‑selector rule. [pending]

- Docs & Samples
  - README and Module docs: “Profiles and Parity” with a small matrix of features and links to Word/Markdown/HTML/Excel examples. Include paths to Projects/HtmlForgeX/HtmlForgeX.Examples/Reports/DomainComplianceReport.cs and Projects/OfficeIMO/OfficeIMO.Examples/Excel/DomainDetective.Report.Sheets.cs. [pending]
  - Add Module/Examples scripts that generate all formats for the same input and save side‑by‑side artifacts. [pending]
  - HTML component guidance: accordions/tabs/KPI cards/data grids reference demos under Projects/HtmlForgeX/HtmlForgeX.Examples/Containers — ComponentHtmlContainer03.cs, ComponentHtmlContainer04.cs, AccordionStepsShowcase.cs, SmartTabDemo.cs, DataGridShowcase.cs, TablerDashboardDemo.cs. [pending]

Format/Profile Matrix (target parity)

| Format            | Profile    | TOC | Exec. Summary | Providers | Per‑Domain Sections | Notes |
|-------------------|------------|-----|---------------|-----------|---------------------|-------|
| Word              | Document   | Yes | Yes           | Yes       | Yes                 | Canonical reference |
| Markdown          | Document   | Yes | Yes           | Yes       | Yes                 | Mirrors Word layout |
| MarkdownHtml      | Document   | Yes | Yes           | Yes       | Yes                 | Markdown → HTML bridge |
| HTML (HtmlForgeX) | Dashboard  | N/A | KPIs + Grid   | Optional  | Optional (accordion)| Mirrors DomainComplianceReport.cs |
| HTML (HtmlForgeX) | Document   | Yes | Yes           | Yes       | Yes                 | Optional full doc mode |
| Excel             | Dashboard  | N/A | KPIs + Grid   | Optional  | No                  | Mirrors DomainDetective.Report.Sheets.cs |
| Excel             | Workbook   | Index | Yes         | Yes       | Yes                 | Per‑sheet details |

## Synthetic Monitoring (Future)
- Uptime checks: scheduled HTTP(S) probe with TLS posture + header checks; trend charts and alert thresholds. Easy
- Latency metrics: TTFB/total per probe; regional vantage points; aggregation. Medium
- Waterfall charts: generate from static scan (HEAD/GET timings) for first-load; store snapshots. Medium
- Alerts/integrations: webhook/Slack/email; certificate expiry warnings (reuse CertificateMonitor). Medium
- Transaction flows (multi-step): optional browser required; model steps, assertions, data entry. Hard
