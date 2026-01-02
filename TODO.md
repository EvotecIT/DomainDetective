# DomainDetective — Open TODO (Consolidated)

This is the single backlog/roadmap file for DomainDetective. Items below were last validated against the codebase on 2026-01-02.

## High Priority
- Golden report pass (Word): single-domain and multi-domain; verify one-liner intros and References blocks across sections.

## Security & Robustness (Hardening)
- Path traversal protection for time-series stores (validate IDN + enforce "under root" paths). [done]
- PowerShell cmdlets: validate `DomainName` parameters via `[ValidateDomainName]`. [done]
- PowerShell `Test-DnsPropagation`: prevent relative `-ServersFile` escaping module directory. [done]
- DNS propagation: guard null `Location`/`Country` metadata during distributed server selection. [done]
- CLI: warn on `--imap-password` usage and prompt when interactive to avoid shell history leaks. [done]
- CLI report generation: stop swallowing conversion exceptions; surface warnings for failed conversions. [done]
- Subdomains resolution verification: add configurable rate limiting + CLI knobs. [done]
- DNS amplification: cap resource limits, harden DNS response parsing, and remove null-forgiving misuse. [done]
- TLS probe: remove empty catch blocks and refactor duplicated probe logic. [done]
- CT timeline parsing: split `ParseCtJson` into focused helpers. [done]
- Follow-up: consider upstreaming DNS parsing/rate limiting helpers to `DnsClientX`. [pending]

## Reports — Word
- Optional: CLI surface for summary column cap (default 4 content columns). PS is wired via `Set-DDExportOptions -SummaryColumnCap`.

## Competitive Parity (External Feature Gaps)
- Resolver override everywhere
  - Expose multi-resolver lists across CLI/PS beyond the full health cmdlet; pipe through to DNS layer.
    - PowerShell: base cmdlet params applied across cmdlets. [done]
    - CLI: `check` + `report` support multi-resolver list + strategy. [done]
    - CLI: extend to remaining commands. [pending]
- Bulk input and CSV export
  - Add `-InputFile` to CLI/PS to process domain lists.
  - Add `-CsvPath` for first-class CSV export without requiring downstream piping.
- DKIM selector targeting (CLI)
  - Expose explicit selector list override; roll up worst severity across selectors.
- DNSAudit-style DNS security checks (gap closure, based on 2026-01-01 JSON exports)
  - DNS Cookies (RFC 7873): test EDNS COOKIE support per authoritative NS; surface as Info/Warning with remediation guidance. [done]
  - TXT malware heuristics: scan TXT (apex + selected subdomains) for high-entropy/encoded payloads and suspicious command patterns; cap evidence and avoid noisy false positives. [done]
  - TXT service exposure signals: expand TXT token detector to include common ownership/search verification records (e.g., Bing `msvalidate.1=`) and surface as Inventory/Info. [done]
  - Sensitive subdomains highlighting: flag CT/discovered subdomains with high-risk labels (e.g., login/vpn/admin/smtp/intranet/finance/payments) when publicly resolvable; support allow/deny lists. [done]
  - Subdomain spoofing protection: evaluate DMARC `sp=` vs. wildcard SPF (`*.domain`) posture; prefer DMARC guidance but optionally detect and recommend wildcard SPF when appropriate. [done]
  - DKIM key reuse detection: detect identical DKIM public keys across selectors/domains within a run; flag as risk/operational smell and recommend key rotation. [done]
  - IPv6 readiness roll-up: summarize apex AAAA + MX IPv6 support + NS IPv6 glue/reachability into a single “Incomplete IPv6” advisory. [done]
  - Open resolver anomaly detection: when recursion is not confirmed open, still surface unusual flags/rcodes/TC/timeouts as “anomalous DNS response” (low severity). [done]
  - DNS amplification posture: combine open recursion + EDNS UDP size/truncation + bounded “large answer” probes to flag reflection potential; avoid aggressive scanning. [done]
  - DNS over TLS support: probe TCP/853 + TLS handshake on authoritative NS endpoints; surface as Info/Warning with remediation guidance. [done]
  - Service discovery exposure: in extended inventory, flag SRV/NAPTR/LOC/HINFO/SSHFP/etc. records and provide a concise “what this reveals” advisory (configurable suppress). [done]
  - DNS inventory extended profile: optional extended record-type sweep (SRV/NAPTR/TLSA/SMIMEA/SSHFP/OPENPGPKEY/SVCB/HTTPS/DS/DNSKEY/RRSIG/NSEC/NSEC3PARAM/…) with safe caps and reporting. [done]
  - Private IP / rebinding signals: flag apex/subdomain A/AAAA answers in private/loopback/link-local/ULA ranges; integrate with propagation to detect split-horizon. [done]
  - DNS server fingerprinting: CHAOS `version.bind`/`hostname.bind` (warn on disclosure); optional CVE mapping is deferred. [done]
  - AI/ML exposure patterns: optional detector for common AI infra/service hostnames (subdomains/CNAME/TXT) using a small ruleset similar to `TechRules.json` (opt-in). [done]

## Discovery & Inventory (Parity + Beyond)
- Certificate transparency (CT)
  - CT-backed domain timeline (first/last seen, issuer diversity, active vs expired, anomalies). [done]
  - CT-backed subdomain discovery with `FirstSeenUtc`/`LastSeenUtc` and optional DNS “still resolves” verification (bounded + concurrent). [done]
  - CT result hygiene: wildcard normalization, IDN normalization, deduping, safe caps for very large domains, clear failure modes. [done]
- DNS inventory + insights
  - Single-pass DNS inventory (common record types + TTLs + authority) exposed as a typed model. [done]
  - Provider/technology inference for DNS records (NS/MX/CNAME/TXT/CAA) using an enum + deterministic matchers (avoid heavy regex; AOT-friendly where possible). [done]
  - Authoritative trace mode (iterative resolution + trace log) for explainability and debugging. [done]
- DNS propagation
  - Multi-resolver propagation check (per record type) with answer-set comparison, country rollups, and map visualization in HTML. [done]
  - Reporting parity: HTML + Word + Excel composition sections. [done]
  - Dashboard rollups (KPIs/legend for propagation drift and inconsistency). [done]
- IP enrichment
  - First-class IP enrichment layer (ASN/org, geo, reverse DNS) with caching and minimal external dependencies. [done]
    - Inputs: apex A/AAAA + optional MX/NS host IPs (bounded) and/or caller-supplied IP list.
    - Outputs: typed rows (IP, source host/kind, PTR, ASN, AS name, CIDR/prefix, country/region) + summary counts.
    - Caching: in-memory per run (keyed by IP); future: disk-backed store (JSONL/SQLite).
    - Surfaces: HTML/Word/Excel composition section + view object with `.Raw`.
  - Pluggable providers (offline-first; online enrichers optional) and deterministic output schema for reporting. [done]
    - Offline: GeoIP (embedded DB), reverse DNS (DNS).
    - Online (optional): RDAP IP + ASN lookup (standard; overrideable base URL/file).
- HTTP posture knobs
  - Request customization for HTTP posture checks: method (HEAD/GET/…), custom request headers/cookies, proxy, and optional TLS validation relaxation (off by default). [done]
    - Persist effective URL/redirect chain and request method used.
    - Ensure HTTPS-only semantics (e.g., HSTS missing suppressed for non-HTTPS effective URLs).
    - CSP-aware rules (e.g., XFO optional when CSP `frame-ancestors` is present).
  - Separate buckets for security / caching / information-disclosure / deprecated headers in outputs. [done]
    - Evidence tables: present + missing security headers; present info-disclosure headers; present caching headers; deprecated present/missing (if requested).
- Reporting parity
  - Add “Discovery” sections to Word/HTML/Excel (Document profile): CT timeline + subdomain table + DNS inventory + insights + evidence blocks. [done]
  - Add Dashboard widgets (HTML/Excel): key discovery KPIs (subdomains, cert issuance velocity, provider mix, IP/HTTP rollups). [done]
  - Add Dashboard drift indicators (requires run store / snapshots). [deferred]
- Future storage (not now)
  - Optional local run store for discovery snapshots (JSONL now; SQLite later via `DBAClientX`) to enable drift detection and timelines. [deferred]

## Surpass Moves (Go Beyond Parity)
- RDAP-first with WHOIS fallback; structured JSON with IANA/IETF status semantics.
- Enforcement readiness scores
  - DMARC: compute readiness to move to `p=reject` (alignment, pass rate trends, authenticated percentage).
  - MTA-STS/TLS-RPT: readiness to move to `mode=enforce` (MX coverage, TLS grades, report coverage).
- Portfolio drift detection across runs (registrar, NS, MX, TLS posture) with concise diff in reports.
- MX TLS coverage matrix per domain (each MX host: STARTTLS, min TLS version, cert validity, SNI behavior) summarized in Word/HTML.
- PS/CLI: `-Server` multi-resolver strategies exposed (FirstSuccess/FastestWins/SequentialAll) with timeouts and IPv6 preference.
- HTML report polish: sticky TOC, anchors, and expandable "+N more" lists consistent with Word summary behavior.
## CLI / PowerShell
- CLI: expose company branding options (CompanyName/Address/Year/Logo/Header/Watermark) and pass to composition.
- CLI packaging: single-file builds + native package feeds (Windows/macOS/Linux).
- CLI/PS: opinionated presets and batch modes for scheduled audits.
- PS: `-ShowPositives` switch for table views to list posture signals quickly.
- Posture one-liner: CLI `--posture`, PS `-Posture` to emit condensed controls line and JSON variant.
- Wizard: HTML export parity (reuse posture panels).
- Persona: optional concise mode (cap line length per stage).
## Networking / Resolvers
- DNS Resolver Override (PS + Core)
  - Batch API preserving order. [done]
  - Endpoint validation and toggles
    - Friendly errors for invalid endpoints. (pending)
    - Global per‑query/per‑endpoint timeouts. (pending)
    - TTL passthrough surfaced where useful. (pending)
  - PowerShell/CLI surface
    - Extend to other testing cmdlets (PowerShell base cmdlet params). [done]
    - Extend to other CLI commands. [pending]
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

## Deferred (Not Needed Now)
- PDF: move from minimal output to composition-based parity (Word/HTML structure, branding, references).

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
  - HTML visualization components (HtmlForgeX)
    - Vector map legend + consistent tooltip formatting for heatmaps. [pending]
    - Lightweight chart primitives (sparkline, bars) for time-series rollups. [pending]
    - "Expandable list" component to standardize "+N more" UX. [pending]
    - Table export helpers (CSV/Excel) for DataTables-style tables. [pending]

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
