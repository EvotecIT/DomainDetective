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
- [ ] MX integrity: cross‑NS RRset consistency (serialize A/AAAA per NS and diff).
- [ ] MX integrity: TTL uniformity across MX RRset and their A/AAAA.
- [ ] DNSSEC: NSEC3 Opt‑Out verification; code Dnssec.Nsec3OptOutRisk.
- [ ] EDNS: warn on fragmentation risk (advertised >1232 without PMTU) — Edns.BufferTooLarge; track resolver fallback.
- [ ] STARTTLS/SMTPTLS grading: coarse grade A/B/C/D/F (protocols, TLS ver, key size, chain validity, expiry, hostname match).
- [ ] TLS legacy: emit Tls.LegacyEnabled when SSLv3/TLS1.0/1.1 allowed.
- [ ] Reverse DNS: Ptr.ForwardMismatch when PTR→A/AAAA does not map back; Ptr.SharedCloudManyToOne advisory.
- [ ] IP Neighbors: categorize neighbors; warn MailOnSharedIp when MX/SMTP on high co‑tenancy IP.
- [ ] WHOIS: cache TLD→server within session; backoff/retry on transient TCP failures; extend EU ccTLD parser coverage.

## Type Consistency & Views
- [ ] Normalize `Subject` type usage across converters (domain vs host:port vs URL); document per‑converter expectations.
- [ ] Add `Area` mapping in views for grouping (Mail/DNS/Web/Security) and expose in CLI/PS renders.
- [ ] Add single‑line `Summary` per view for compact dashboards.
- [ ] SPF view: add `RecordLength`, ensure `DnsLookupsCount` naming is consistent; align recommendations to RFC 7208 size and lookup limits.
- [ ] Ensure status/warning/error counts aggregate identically in C#, CLI JSON, and PS outputs.

## DNS Resolver Override (PS + Core)
- [ ] Validate IPv4/IPv6 endpoints; allow multiple resolvers with first‑success semantics (extend `DnsConfiguration`).
- [ ] Unit tests: override honored and graceful fallback on unreachable resolvers.
- [ ] Docs: examples for vendor presets and `DnsEndpoint` usage.

## DKIM Selector Coverage
- [ ] Add DKIM auto‑detect tests for new selectors; assert advisory/key parsing results.

## DMARC Aggregate (RUA)
- [ ] Unify Test‑DDDmarcAggregate to use `DmarcReportParser` (v1+v2; xml/gz/zip) and add `-SummarizeBy Ip|HeaderFrom`.
- [ ] Compute and expose `RequestedReportingPolicy` from `policy_published.fo`.
- [ ] Support directory/glob ingestion; optional de‑dup by report‑id + date range.
- [ ] Optional export params `-CsvPath` and `-Json` for records/summaries.

## Testing & Validation
- [ ] Snapshot tests for updated converters to verify `Status`, `WarningCount`, `ErrorCount`, `References`.
- [ ] Integration tests: confirm assessments appear under correct `Subject` scopes (e.g., per‑server).
- [ ] Pester smoke tests: adapt deep asserts to `view.Raw`.

## Docs
- [ ] Extend XML examples for enums/classes (TLS enums, DnsEndpoint usage, etc.).
- [ ] Cmdlet XML remarks: “Outputs a view object with full raw analysis at Raw”.
- [ ] Add quick dashboards examples in `Docs/REPORTING_USAGE.MD` using Select‑Object, and `view.Raw` for deep data.

## Providers & Recommendations (Remaining)
- [ ] WHOIS provider (query failure, parsing anomalies).
- [ ] RDAP provider (request failure, status handling).
- [ ] Open Relay provider (check failure mapping).
- [ ] DNSBL provider (listed, per‑provider query failures).
- [ ] NS/SOA provider (misconfig, serial skew, MNAME/RNAME format, refresh/retry extremes).
- [ ] IP Neighboring provider (passive DNS failures, high‑risk neighbors if defined).
- [ ] HTTP advice examples/snippets (nginx/Apache/Cloudflare) in `How` for common fixes.
- [ ] Header value quality checks (e.g., X‑Frame‑Options values; Permissions‑Policy parsing).

## Persona (CLI + PowerShell)
- [ ] Ensure persona formatting parity between CLI and PowerShell (AssessmentNarrator + PersonaKind shared usage) in docs and examples.
- [ ] Document persona toggles: CLI `--persona`, `--persona-live`, `--persona-verbose`; PS `Set‑DDPersona` and wizard defaults.
- [ ] Add examples showing per‑section persona log panels paired with recommendations (already in CLI — ensure PS docs show equivalent experience).

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
- [ ] Validate JSON shape stability and type naming across versions (align with PS outputs and C# view contracts).
- [ ] Minor UX: compact inline operation names in progress table; keep under 80 chars to avoid flicker (audit long names).

## Stretch Ideas
- [ ] MTA‑STS deep dive (policy caching, redirects, expiry, enforce only when all MX support TLS).
- [ ] TLS OCSP stapling and SCT presence checks (Tls.OcspMissing, Tls.SctMissing advisories).
- [ ] Threat intel scoring: severity weighting by source and recency.
- [ ] Passive DNS cache to reduce rate‑limits and speed neighbor checks.

—

Notes
- Focus first on core + PowerShell; CLI UX comes last but should reuse the same types and views.
- Keep new codes/providers under `Diagnostics/Recommendations/` with stable codes and authoritative links.
