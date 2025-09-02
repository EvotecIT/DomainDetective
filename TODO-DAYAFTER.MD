# DomainDetective — Consolidated TODO (Day-After First)

This single TODO consolidates all open items from previous docs, removes completed work, and orders priorities as requested: Day‑After tasks first, then general/core items, Persona one‑before‑last, CLI improvements last. Emphasis: consistency and improvement of types across C# views, CLI, and PowerShell.

## Guiding Principles
- Prefer precise, RFC‑aligned checks over heuristics.
- Views are lossless: expose `Raw`, `Assessments`, `Status/Counts`, and `Recommendations`.
- Scope `Subject` to actionable granularity (domain, host:port, URL, RRset).

## Day‑After Priority (High‑Impact)
- [x] DirectoryExposure: expand default paths (.bak, ~, _backup/, .DS_Store, package-lock.json, yarn.lock, sitemap.xml|.txt, .well-known/security.txt).
- [x] DirectoryExposure: new findings per class — Secrets.DotEnv, Backups.Present, SourceMap.Exposed.
- [x] Apex address analysis: normalize PTR hostnames (trim dot, lowercase) prior to forward checks.
- [x] Apex address analysis: when overrides exist but A/AAAA empty, hydrate from overrides and PTR hostnames.
- [x] Add unit test for Apex_HasAOnly to lock behavior.
- [x] MX integrity: cross‑NS RRset consistency (serialize A/AAAA per NS and diff).
- [x] MX integrity: TTL uniformity across MX RRset and their A/AAAA.
- [x] DNSSEC: NSEC3 Opt‑Out verification; code Dnssec.Nsec3OptOutRisk.
- [x] EDNS: warn on fragmentation risk (advertised >1232 without PMTU) — Edns.BufferTooLarge; track resolver fallback.
- [x] STARTTLS/SMTPTLS grading: coarse grade A/B/C/D/F (protocols, TLS ver, key size, chain validity, expiry, hostname match).
- [x] TLS legacy: emit Tls.LegacyEnabled when SSLv3/TLS1.0/1.1 allowed.
- [x] Reverse DNS: Ptr.ForwardMismatch when PTR→A/AAAA does not map back; Ptr.SharedCloudManyToOne advisory.
- [x] IP Neighbors: categorize neighbors; warn MailOnSharedIp when MX/SMTP on high co‑tenancy IP.
- [x] WHOIS: cache TLD→server within session; backoff/retry on transient TCP failures; extend EU ccTLD parser coverage. (added generic EU parser and session cache)

### External Feature Parity (from Demo/Pages screenshots)
The following items come from reviewing examples in `Demo/Pages` (securityheaders.com, HeaderScan, SSL Labs, CheckTLS, DNSChecker, Sucuri/SSLTrust, Sitechecker). They capture gaps and desired parity.

- [x] Web: HTTP Security Headers analysis and grade (parity with SecurityHeaders/HeaderScan)
  - [x] Detect HSTS, CSP, Referrer‑Policy, X‑Content‑Type‑Options, X‑Frame‑Options, Permissions‑Policy
  - [x] Flag upcoming COEP/COOP/CORP as advisories
  - [x] Capture RawHeaders; per‑header quality checks + recommendations
  - [x] Compute concise letter grade and add summary counts in view/CLI/PS

- [x] Web: HTTPS/TLS analysis (parity with SSL Labs, at coarse level)
  - [x] Hostname/chain validity, expiry, key size, SHA2, issuer
  - [x] Protocol/cipher support matrix incl. TLS1.0–1.3; weak/deprecated flags (coarse level covered by grade)
  - [x] ALPN detection (h2/h3), SCT presence count (CT queries wired)
  - [x] Overall web TLS grade (A/B/C/D/F) aligned to mail TLS grading

- [x] Mixed‑Content and insecure forms (parity with Sitechecker)
  - [x] Detect mixed content on HTTPS page
  - [x] Report insecure `form action` and example URLs
  - [x] Counts + representative examples; add recommendations

- [x] Website blacklist/malware aggregation (parity with Sucuri/SSLTrust)
  - [x] Pluggable providers (OpenPhish hook, PhishTank, URLHaus; optional Google Safe Browsing via API key)
  - [x] Aggregate status with per‑provider evidence and caching/backoff

- [x] DNS Health deep checks (parity with DNSChecker Health)
  - [x] NS recursion disabled test; public AXFR open test (existing in NS/AXFR analyses)
  - [x] Glue/in‑bailiwick validation; A/AAAA consistency across NS (DnsHealthAnalysis)
  - [x] SOA serial skew across NS (DnsHealthAnalysis)
  - [x] TTL uniformity across common RRsets (A/AAAA/CNAME/NS) across authoritative servers

- [x] Mail hardening extras
  - [x] MTA‑STS status (policy mode, max_age, MX alignment)
  - [x] TLSRPT endpoint resolution and sanity checks (optional HEAD)
  - [x] DANE/TLSA validation for MX (alignment advisories)

- [x] Certificate transparency and stapling
  - [x] OCSP stapling presence checks (web + mail); advisory when missing
  - [x] SCT presence count; advisory when none embedded

## Autodiscover (Enrichment & Coverage)
- [x] Aggregate HTTP endpoints into Autodiscover view (attempt counts, success, best URL/status, redirects, HTTPS/HTTP split)
- [x] Expand endpoint coverage and validation
  - [x] Follow redirect chains to final host and record it (o365, etc.)
  - [x] Optional content sniff (first KB) to detect HTML error pages vs XML
  - [x] Validate XML root/namespace against expected Autodiscover schema
  - [x] Advisory when CNAME → outlook.com but HTTP flow fails (network/SNI hint)
  - [x] Outlook v2 JSON domain discovery + follow‑up POST to discovered URL

## DKIM Selector Coverage
- [x] Add DKIM provider selector heuristics (Google, M365, SendGrid, Mailgun, SparkPost, Zoho, Campaign Monitor, HubSpot, etc.)
- [ ] Add DKIM auto‑detect tests for new selectors; assert advisory/key parsing results (partially added; one failing test remains)

## Type Consistency & Views
- [x] Replace string `Area`/`Check` with enums across views
  - [x] Add `AnalysisArea { General, DNS, Mail, Web, Security }`
  - [x] Use `HealthCheckType` for `Check` (HTTP, CERT, DANE, DNSHEALTH, MX, SPF, DKIM, DMARC, NS, SOA, EDNSSUPPORT, WILDCARDDNS, ZONETRANSFER, OPENRESOLVER, OPENRELAY, STARTTLS, SMTPTLS, IMAPTLS, POP3TLS, SMTPBANNER, SMTPAUTH, TLSRPT, MTASTS, SMIMEA, DNSBL, RDAP, WHOIS, RPKI, IPNEIGHBOR, PORTSCAN, PORTAVAILABILITY, DNSTUNNELING, SECURITYTXT, WEBSITE, APEXADDRESS, SPFFLATTENED, MAILCLASSIFICATION)
  - [x] Update `Converters.AreaForKind(HealthCheckType)` and remove legacy string mapping
  - [x] CLI/PS renderers consume enums (render via `ToString()`); JSON uses enum-as-string
- [x] Add single‑line `Summary` per view for compact dashboards.
- [x] SPF view: add `RecordLength`, ensure `DnsLookupsCount` naming is consistent; align recommendations to RFC 7208 size and lookup limits.
- [x] Ensure status/warning/error counts aggregate identically in C#, CLI JSON, and PS outputs.
- [x] Normalize `Subject` usage across major converters
  - [x] Set Subject for: Autodiscover, RPKI, TLSRPT, EDNSSUPPORT, ZONETRANSFER, DANGLINGCNAME, CONTACT, DNSTUNNELING, SPF‑FLAT, FCRDNS, APEXADDRESS
  - [ ] Decide policy for multi‑host views (PortScan/PortAvailability/MailLatency) — leave blank vs “host:port” for single‑target runs; document choice
  - [ ] Review DNSBL view Subject (currently picks representative key) — consider explicit domain Subject alongside per‑host lists

## Autodiscover (Enrichment & Coverage)
- [x] Aggregate HTTP endpoints into Autodiscover view (attempt counts, success, best URL/status, redirects, HTTPS/HTTP split)
- [ ] Expand endpoint coverage and validation
  - [ ] Follow redirect chains to final host and record it (o365, etc.)
  - [ ] Optional content sniff (first KB) to detect HTML error pages vs XML
  - [ ] Validate XML root/namespace against expected Autodiscover schema
  - [ ] Advisory when CNAME → outlook.com but HTTP flow fails (network/SNI hint)
  - [ ] CLI/PS: toggle to display top endpoint verdict inline

## DNS Resolver Override (PS + Core)
- [ ] Integrate DnsClientX multi‑resolver APIs in `DnsConfiguration`
  - [ ] Wire `IDnsMultiResolver` (FirstSuccess as default) for `QueryDNS`/`QueryFullDNS`
  - [ ] Support `MultiResolverOptions` (Strategy: FirstSuccess|FastestWins|SequentialAll; MaxParallelism; PreferIPv6; AllowTcpFallback)
  - [ ] Accept resolver list as `DnsResolverEndpoint[]` and parse strings: `1.1.1.1:53`, `[2606:4700:4700::1111]:53`, `dns.google:53`, `https://dns.google/dns-query`
  - [ ] Adopt `QueryBatchAsync` for batch lookups while preserving input order
- [ ] Endpoint validation and toggles
  - [ ] Validate IPv4/IPv6 endpoints; friendly errors when invalid/blocked
  - [ ] Global per‑query timeout + per‑endpoint timeout; propagate cancellation tokens
  - [ ] TTL passthrough (min/avg) when available on responses (surface on views where useful)
- [ ] Tests
  - [ ] Override honored; graceful fallback on unreachable resolvers
  - [ ] IPv6‑only and IPv4‑only scenarios; mixed family selection
  - [ ] Batch preserves order and isolates failures
- [ ] Docs
  - [ ] Vendor preset examples (Cloudflare/Google/Quad9/DoH) and `DnsEndpoint`/resolver string formats
  - [ ] Brief strategy guidance (FirstSuccess vs FastestWins vs SequentialAll)

## DKIM Selector Coverage
- [ ] Add DKIM auto‑detect tests for new selectors; assert advisory/key parsing results.

## DMARC Aggregate (RUA)
- [x] Unify Test‑DDDmarcAggregate to use `DmarcReportParser` (v1+v2; xml/gz/zip) and add `-SummarizeBy Ip|HeaderFrom`.
- [x] Compute and expose `RequestedReportingPolicy` from `policy_published.fo`.
- [x] Support directory/glob ingestion; optional de‑dup by report‑id + date range.
- [x] Optional export params `-CsvPath` and `-Json` for records/summaries.

## Testing & Validation
- [ ] Snapshot tests for updated converters (Autodiscover, TLSRPT, EDNSSUPPORT, RPKI) to verify `Status`, counts, `Summary`, `References`.
- [ ] Integration tests: confirm assessments appear under correct `Subject` scopes (e.g., per‑server).
- [ ] Pester smoke tests: adapt deep asserts to `view.Raw`.

## Docs
- [ ] Extend XML examples for enums/classes (TLS enums, DnsEndpoint usage, etc.).
- [ ] Cmdlet XML remarks: “Outputs a view object with full raw analysis at Raw”.
- [ ] Add dashboard examples in `Docs/REPORTING_USAGE.MD` using Select‑Object, and `view.Raw` for deep data.
- [ ] Document Subject conventions per view (domain vs host:port vs URL) and rationale.

## Providers & Recommendations (Remaining)
- [x] WHOIS provider (query failure, parsing anomalies).
- [x] RDAP provider (request failure, status handling).
- [x] Open Relay provider (check failure mapping).
- [x] DNSBL provider (listed, per‑provider query failures).
- [x] NS/SOA provider (misconfig, serial skew, MNAME/RNAME format, refresh/retry extremes).
- [x] IP Neighboring provider (passive DNS failures, high‑risk neighbors if defined).
- [x] HTTP advice examples/snippets (nginx/Apache/Cloudflare) in `How` for common fixes).
- [x] Header value quality checks (e.g., X‑Frame‑Options values; X-Content-Type-Options).

## Next Session — Stretch Goals
- HTTP hardening
  - [x] Add COOP/COEP/CORP advisories with remediation snippets
  - [x] Expand CSP linting (unsafe-inline/unsafe-eval detection; report-only guidance)
  - [x] Permissions‑Policy value validation and common templates
- WHOIS/RDAP
  - [x] Add vendor‑specific WHOIS parsers beyond generic EU fallback (e.g., .de, .uk nuances)
  - [x] Cache/TTL policy docs and tunables for rate‑limited registries
- Threat Intel
  - [x] Score aggregation (severity/recency weighting) and normalized confidence
  - [x] Passive DNS cache to reduce rate‑limits and speed neighbor checks (implemented in IPNeighborAnalysis session cache)
- CLI/PS UX
  - [ ] Wizard HTML export (parity with JSON; reuse posture panels)
  - [ ] Inline Autodiscover endpoint verdict row in summaries (toggle)
  - [ ] Persona: optional concise mode to cap line length per stage
- TLS/Email
  - [x] Extend mail TLS cipher reporting (curve/key exchange) and weak suites mapping
  - [x] DKIM: add more provider selector heuristics
  - [ ] DKIM: add auto‑detect tests for new selectors; assert advisory/key parsing
- Validation
  - [ ] Add snapshot tests for enriched Autodiscover and Subject policies

## Persona (CLI + PowerShell)
- [x] Ensure persona formatting parity between CLI and PowerShell (AssessmentNarrator + PersonaKind shared usage) in docs and examples.
- [x] Document persona toggles: CLI `--persona`, `--persona-live`, `--persona-verbose`; PS `Set‑DDPersona` and wizard defaults.
- [x] Add examples showing per‑section persona log panels paired with recommendations (already in CLI — ensure PS docs show equivalent experience).

### Persona — Definition & Behavior
- Concept: A persona is a presentation layer for logging and assessment narration. It applies consistent icons, colors, phrasing, and optional emojis to every Info/Warning/Error the user sees in console UIs (CLI and PowerShell). It never alters JSON/HTML payloads.
- Scope: All InternalLogger messages (Info/Warning/Error) and assessment summaries are formatted through persona. In CLI, this surfaces in Live Narration and final Recommendations panels. In PS, persona formats streaming logs; returned objects remain unchanged.
- Channels:
  - Console (Spectre): styled with markup (colors/icons), respects persona; Live UI and simple streaming both supported.
  - PowerShell host: styled text with icons where supported; no change to output objects.
  - JSON/HTML: persona is not applied. These outputs must remain clean, semantic, and style‑free.
- Determinism: Phrase selection should be stable (e.g., hash by `Code` + `Category` to pick a phrase) to avoid random wording between runs. Emoji usage follows `EmojiDensity` but can be seeded for stability.
- Severity mapping: Icons and colors vary by severity. Category/Target remain intact for context. Example structure: `icon [bold]{Category}[/] (Target): narrated text`.
- Length & ergonomics: Keep live lines concise (< ~100 chars) to reduce flicker; progress overlays display only short “Now” operation names.

### Persona Profile Schema (reference)
Use a profile with the fields below; CLI and PS should render from the same underlying profile where possible.

```csharp
new PersonaProfile {
    Name = "business",
    StageTagColor = "bold steelblue1",
    StepColor     = "deepskyblue1",
    OkColor       = "green3",
    WarnColor     = "khaki1",
    ErrColor      = "red3",
    PromptIcon = "»",
    OkIcon    = "✓",
    WarnIcon  = "⚠",
    ErrIcon   = "✖",
    StepVerbs   = new[]{ "Checking","Verifying","Evaluating","Assessing","Analyzing" },
    OkPhrases   = new[]{ "Confirmed","All good","Compliant","Healthy","Meets policy" },
    WarnPhrases = new[]{ "Needs attention","Advisory","Degraded","Weak posture","Consider changes" },
    ErrPhrases  = new[]{ "Non-compliant","Failed","Broken","Critical","Blocking" },
    EmojiDensity     = 0.05,
    Emojis           = new[]{ "📈","🧭","🧩" },
    StepTypeSpeedMs  = 12,
    ResultTypeSpeedMs= 8
}
```

Implementation notes
- Map InternalLogger → PersonaFormatter → rendered line. Use `AssessmentNarrator` for content, Persona profile for styling.
- CLI flags: `--persona business|funny|geek|noir|pirate`, `--persona-live`, `--persona-verbose`. Simple UI still applies persona (minimal markup).
- PowerShell: `Set‑DDPersona -Persona Business -Live -NarrateVerbose` controls live narration; objects are unaffected (views carry Assessments/Recommendations as types).
- Tests: Verify persona formatting covers all severities; phrase selection is deterministic; JSON/HTML outputs contain no persona markup.

## CLI Improvements (Last)
- [ ] HTML export for wizard mode (parity with JSON; reuse RecommendationViews and posture panels).

## Web Scanning (urlscan‑style, Pingdom Later)

Goal: Add a static (no‑browser) web scanner first, then an optional dynamic/browser flow later (via HtmlTinkerX/Playwright) — topped off with Pingdom‑style synthetic monitoring. Ordered top→bottom from easiest to hardest. Items marked Non‑Browser do not add heavy dependencies.

### Non‑Browser (Static Web Scan MVP)
- [x] Resource discovery (HTML): GET main page, parse <script|link|img|iframe|video|audio|source|picture/srcset>; resolve relative URLs. Easiest
- [x] Resource metadata: HEAD per resource (small GET fallback); capture status, content‑type/length, redirects, timings. Easiest
- [x] TLS per host: SslStream handshake; protocol/cipher suite; cert issuer/SANs/expiry; OCSP stapling via existing OpenSSL helper. Reuse from MailTlsAnalysis by extracting TlsProbe helper. Easy
- [x] Security posture (main doc): reuse HttpAnalysis to assess HSTS, CSP, Referrer‑Policy, COOP/COEP/CORP, mixed content, insecure forms. Easy
- [x] CSS url(...) extraction: fetch linked CSS (size/time capped), extract url(...) and enqueue; support @import. Medium
- [x] DNS/ASN/country enrichment: resolve contacted hosts, cache; optional RDAP/ASN lookup with TTL. Medium
- [x] First vs third‑party classification: registrable domain via PSL; per‑host/request totals. Medium
- [x] Tracker detection (curated): small bundled list (Disconnect/EasyPrivacy subset) for domain/path matches. Medium
- [x] Tech fingerprints (heuristic): headers (Server, X‑Powered‑By), meta generator, common file paths (wp‑, drupal, jquery), cookie names. Medium
- [ ] Threat intel overlay: run ThreatIntelAnalysis for each contacted registrable domain; add severity/score/recency to host table. Medium
- [ ] Reporting: HTML section in SimpleDomainReport + CLI summary (top hosts, bytes by type, posture, TLS, trackers, threat intel). Medium
- [x] PowerShell cmdlet Test‑DDWebStaticScan: parameters (Url, MaxSeconds, MaxResources, Concurrency, RespectRobots, SkipThreatIntel, SaveArtifactsPath); outputs typed view. Medium
  - Implemented as `Test-DDWebsiteStaticScan` with aliases (`Test-DDWebStaticScan`, `Test-WebsiteStaticScan`, `Test-WebStaticScan`). `-Url` has alias `-DomainName`; supports bare domains; tracks redirects. Added `-SkipThirdParty` and concurrency/robots switches.
- [ ] Artifacts: write scan.json (HAR‑like), resources.csv, hosts.csv under ./artifacts/<host>/<timestamp>/; enforce budgets (time/requests/per‑host caps). Medium
- [x] Concurrency/fairness: bounded parallelism, per‑host limits, retries with backoff; robots.txt optional respect. Medium

### Beyond urlscan (Static Extras)
- [ ] TLS OCSP stapling summary per host; issuer chains and expiry heatmap.
- [ ] CSP quality lint with actionable remediation snippets (nginx/Apache/Cloudflare) — reuse HttpRecommendations.
- [ ] RPKI/RDAP overlay: per‑host origin ASN/org, optional ROA validity indicator.
- [ ] Weak certificate/key detection (e.g., RSA<2048, SHA‑1 signatures); grading similar to mail/web TLS.

### Browser‑Assisted (Dynamic, Optional — HtmlTinkerX Later)
- [ ] Dynamic requests: capture XHR/fetch/WebSocket initiated after load; full network trace (HAR). Hard
- [ ] Runtime signals: console logs/warnings, JS errors, CSP violation reports. Hard
- [ ] Storage: cookies/localStorage/sessionStorage snapshots. Hard
- [ ] Screenshots: full‑page and above‑the‑fold. Hard
- [ ] Timing metrics: DOMContentLoaded, Load, Navigation Timing, and (optionally) Web Vitals (LCP/CLS/FID). Hard
- [ ] Script coverage/blocklists: measure third‑party weight, simulate blocking categories. Hard

Note: Keep this dependency optional; wire via HtmlTinkerX/Playwright only at the last stage, behind a CLI/PS flag.

### Pingdom‑Style Synthetic Monitoring (Future)
- [ ] Uptime checks: scheduled HTTP(S) probe with TLS posture + header checks; trend charts and alert thresholds. Easy
- [ ] Latency metrics: TTFB/total per probe; regional vantage points; aggregation. Medium
- [ ] Waterfall charts: generate from static scan (HEAD/GET timings) for first‑load; store snapshots. Medium
- [ ] Alerts/integrations: webhook/Slack/email; certificate expiry warnings (reuse CertificateMonitor). Medium
- [ ] Transaction flows (multi‑step): optional browser required; model steps, assertions, data entry. Hard

### Components & Reuse
- [x] New: Protocols/WebStaticScanAnalysis.cs orchestrates discovery/fetch/enrichment; exposes Assessments/Recommendations.
- [x] New: Views/Converters.WebStaticScan.cs for CLI/PS/HTML.
- [x] Extract: Protocols/TlsProbe.cs from MailTlsAnalysis to share TLS/cipher/cert/OCSP logic.
- [x] CLI: add --webscan-static; Wizard toggle “Deep web scan (static)”. (Alias `--webscan` added.)
- [x] PS: Test‑DDWebStaticScan cmdlet with export options and persona narration. (Implemented via `Test-DDWebsiteStaticScan` + aliases.)
- [ ] Validate JSON shape stability and type naming across versions (align with PS outputs and C# view contracts).
- [ ] Minor UX: compact inline operation names in progress table; keep under 80 chars to avoid flicker (audit long names).

### Static Web Scan — Data Enrichment (Closed + New)
- [x] DNS TXT verification cache (in‑memory, TTL 5m) to reduce repeats.
- [x] First‑party only mode (SkipThirdParty) to constrain scope on large sites.
- [x] Generator normalization for Blogger, Ghost, Hugo, Jekyll (with version capture where present).
- [x] CDN/Edge provider enrichment per host: fields `EdgeProvider`, `EdgePop`, `EdgeCacheStatus`.
  - [x] Cloudflare: parse `CF-RAY` (PoP), `CF-Cache-Status` (cache result); `Server: cloudflare` as a hint.
  - [x] CloudFront: parse `X-Amz-Cf-Pop` (PoP), `X-Cache` patterns (“ from cloudfront”).
  - [x] Fastly: detect via `X-Fastly-Request-ID`, `X-Timer`, `Surrogate-*`; cache status via `X-Cache`/`X-Cache-Hits`.
  - [x] Azure split: `Azure Front Door` vs `Azure CDN` (headers + suffixes).
  - [x] Akamai: provider and `X-Cache` first‑token parsing (TCP_HIT/TCP_MISS); additional header hints (`X-True-Cache-Key`, etc.).
  - [x] Google Frontend provider hint via `Server: Google Frontend`.
- [x] Safer/expanded domain suffixes: Akamai (edgekey/edgesuite/akamaihd), Azure (azurefd.*, azureedge.net), StackPath, jsDelivr, CDN77, App Engine, Firebase Hosting.
- [x] RDAP fallback: infer provider from ASN/ASName when headers absent (Cloudflare/Fastly/Akamai/AWS/Azure/Google).
 - [x] Per-host posture: `ServerHeader`, `HostHstsPresent`, `CorsAnyOrigin`.
 - [x] Cookie posture summary: first‑party `Secure/HttpOnly/SameSite/Max‑Age/Domain` counts.
 - [x] CORS summary: aggregate ACAO/ACAM/ACAH/credentials across first‑party responses.
 - [x] Server‑Timing summary: aggregate metric names across first‑party responses.
 - [x] Structured data snapshot: count application/ld+json `@type` occurrences.
 - [x] DNS TTL/IPv6 adoption: per‑host A/AAAA TTL min/max + HasIPv6.
 - [x] PoP mapping moved to partial (`WebStaticScanAnalysis.Pops.cs`) and normalized to City/Country/Region.
 - [x] Main body metrics: BodyLength + BodySha256 (decompressed) in `HttpAnalysis`.
 - [x] NEL/Report‑To/speculation headers captured in `HttpAnalysis` (Raw), available for future surfacing.
 - [x] Structured tracker detections: `Raw.TrackerDetails` with Host/Domain, FirstParty, RequestCount/Bytes, SampleUrls, ContentTypes, EvidenceKind/Evidence, TrackerName.
 - [x] Provenance completeness: every `TechDetections` entry gets a `TechDetails` record (fallback heuristic with evidence when needed).
 - [x] Broken resource capture: `Raw.BrokenResources` with StatusCode, Category, Source (HTML/CSS/LINK), FirstParty, Referrer.
 - [x] Per-request protocol: `ProtocolVersion`, `Http2`, `Http3` (from response.Version).
 - [x] Per-request cache/timing headers: `Cache-Control`, `ETag`, `Last-Modified`, `Age`, `Vary`, `Expires`, `Server-Timing`.
 - [x] Per-request header size + overhead: `ResponseHeaderBytes`, `HeaderOverBodyPct`.
 - [x] Per-request CORS echo: `Access-Control-Allow-*` captured alongside scan-level CORS summary.
 - [x] Per-request hints: `Alt-Svc`, `Link` header parsing (preload count, `as=` types).
 - [x] Per-request classification: `ResourceCategory` (enum), `MediaSupertype` (enum), `StatusClass` (enum), `FirstParty`, `SameOrigin`.
 - [x] Per-request TLS/cert provenance stamped from host probe: `TlsProtocol`, `TlsCipherSuite`, `TlsCertSubject/Issuer/NotAfter/Thumbprint`.
 - [x] Link graph: request `Id/ParentId`, `RequestAdjacency` (parent→children), `ChildCount`, `LinkChildCount`, `MaxLinkDepthFromHere`.
 - [x] Redirect taxonomy: `WasRedirected`, `RedirectKind`, `RedirectHopCount`, `RedirectToHost/RedirectToScheme`.
 - [x] Redirect pairs matrix: `RedirectPairs` and `TopRedirectPairs` (by count).
 - [x] Fan-out hotspots: `TopLinkFanOut` (top nodes by link-derived children).
 - [x] Per-host header frequency and summaries: `HeaderCounts`, `HeaderDistinctCount`, `TopHeaders`.
 - [x] Per-host cacheability and freshness: `CacheableResponses/NonCacheableResponses`, `CacheablePercent`, `MaxAgeSecondsMax`, Age header avg/max.
 - [x] Per-host Content-Length presence: `ResponsesWithContentLength/ResponsesWithoutContentLength`, `ContentLengthPresentPercent`.

### Static Web Scan — Missing (Keep Focus on Data, not Output)
- [ ] Threat intel overlay for contacted registrable domains (reuse ThreatIntelAnalysis; optional and capped).
- [ ] Artifact export: compact JSON + CSV for resources/hosts, time‑bounded; add small re‑import viewer later.
- [ ] HTML/JSON/CSV report sections (defer; prioritize enrichment first).
- [ ] Bound concurrency defaults and document caps; validate MaxResources per phase.
- [ ] Add small TTL/state cache across runs (robots, DNS TXT) with invalidation option.
- [x] Per-resource timing (headers timing only) to enable a minimal waterfall later.
 - [ ] SRI/integrity checks for known CDN libraries; flag missing/invalid integrity on first‑party pages.
 - [ ] Summarize first‑party vs third‑party CORS/HSTS ratios at scan level (views) without cluttering objects.

### Static Web Scan — Provider Parity (Offline Features To Implement)
Ordered by impact vs effort. Tags: [QW]=Quick Win, [M]=Medium, [H]=Heavy.

- Redirect quality [QW]
  - Apex↔www consolidation score; http→https coverage; loop detection. [QW]
  - Mean/95p hops for link redirects; top host pairs to consolidate. [QW]

- Caching/CDN posture [QW/M]
  - Detect static assets missing long cache; query‑busting heuristics. [QW]
  - Compression adoption % for textual types; flag uncompressed. [QW]
  - stale‑while‑revalidate / stale‑if‑error presence and maxima. [M]

- SEO/robots static checks [QW]
  - Canonical link presence/mismatch; conflicts. [QW]
  - Robots meta noindex/nofollow on main; sitemap presence via robots (header‑only). [QW]

- HTTP header linting [QW/M]
  - CSP inline/eval counters; frame‑ancestors presence; enforce vs report‑only guidance. [QW]
  - Referrer‑Policy strictness scoring; combine with SameSite posture. [QW]
  - COOP/COEP/CORP maturity score. [M]

- Tracking/cookies posture [QW/M]
  - Third‑party cookies: setting domains; SameSite=None+Secure adoption; cross‑site risk summary. [QW]
  - Third‑party JS weight share; top offenders by bytes (by host/type). [QW]

- IPv6/DNS TTL fitness [QW/M]
  - First/third‑party IPv6 adoption (done) → add critical AAAA gap flags for first‑party hosts. [QW]
  - TTL reasonableness bands (too short/long) by host/type. [M]

- Web TLS deepen (offline) [M/H]
  - Probe minimal version/cipher matrix; ALPN outcomes (h2/h3). [H]
  - Chain quality warnings: AIA issues, duplicate intermediates, Must‑Staple. [M]
  - OCSP stapling freshness window; SCT embedded count summary. [M]

- SPF/DMARC/DKIM depth (mail posture parity) [M/H]
  - SPF include chain depth, void lookups, near‑limit queries, broad ranges; flatten size forecasts. [M/H]
  - DMARC pct<100 and fo modes; rua/ruf syntax/size sanity; alignment advisories. [M]
  - DKIM multi‑selector sampling; weak key/alg flags; b= length sanity. [H]

- DNS hygiene (zone delegation posture) [H]
  - Dangling DS at parent; unsigned child with stale DS. [H]
  - Lame delegation detection; refused/NXDOMAIN/timeout at delegated NS. [H]
  - Glue/authority drift: in‑bailiwick glue vs authoritative A/AAAA mismatch. [H]
  - Tightened nameserver consistency (serial/TTL divergence thresholds). [M]
  - CAA completeness: iodef presence; wildcard vs FQDN policy alignment. [M]

Next Sprint — Quick Wins
- Redirect consolidation scores (apex/www + http→https) with top host pairs.
- Cache/compression adoption stats and advisories for textual assets.
- Canonical/robots meta/sitemap checks on main page.
- CSP/Referrer‑Policy lint (inline/eval, frame‑ancestors, strictness).
- Third‑party JS weight share + top offenders; third‑party cookies posture.
- First‑party AAAA gap flags; TTL band warnings.
### Static Web Scan — Next Enrichment Ideas
- [x] Link-only mode: fast link health audit (anchors only) with depth/pages constraints; skips resource discovery.
- [x] CLI/PS options to control link checker:
  - `FollowLinks` (bool), `LinkMaxDepth` (int), `LinkMaxPages` (int), `LinkFirstPartyOnly` (bool), `LinkConcurrency` (int)
  - PowerShell parameters and CLI flags mirroring these; defaults conservative.
- [ ] PoP tables expansion (more codes) + small ASN→Provider offline map extensions.
- [ ] Link rel hints: capture `preconnect`/`dns-prefetch`/`preload` across pages to infer intended 3P dependencies.
- [ ] PWA signals: discover and parse `manifest.json` (size‑capped); record service worker registration hints (no execution).
- [ ] ASN → Provider offline map expansion for top clouds/CDNs (fallback when RDAP parsing limited).

## Stretch Ideas
- [ ] MTA‑STS deep dive (policy caching, redirects, expiry, enforce only when all MX support TLS).
- [ ] TLS OCSP stapling and SCT presence checks (Tls.OcspMissing, Tls.SctMissing advisories).
- [ ] Threat intel scoring: severity weighting by source and recency.
- [ ] Passive DNS cache to reduce rate‑limits and speed neighbor checks.

—

Notes
- Focus first on core + PowerShell; CLI UX comes last but should reuse the same types and views.
- Keep new codes/providers under `Diagnostics/Recommendations/` with stable codes and authoritative links.
