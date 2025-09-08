# TODO — Tomorrow

This is a short, actionable checklist to pick up work quickly. It reflects the refactors completed today (narrative-driven metadata, positives vs. remediations split, Word header/branding helpers) and focuses on consistency and polish.

## 2025-09-08 (Tomorrow)

Reports (Word)
- [x] DNSBL section writer: add headings + one‑liners (Summary, Findings, Evidence, References) and align with other sections.
- [x] Executive Summary → Overview: include total warnings/errors across all domains in the intro sentence.
- [x] Consolidated Recommendations: for “Domains” column, limit to N items (e.g., 6) then show “+N more”; ensure line wrapping.
- [x] Mail Classification: add a short “Scoring rubric” blurb and link to docs; ensure “Signals considered” renders even when one list is empty.
- [x] Ensure every “References” block starts with a one‑liner (done for SPF/DKIM/DMARC/MX/MTA‑STS/TLS‑RPT/All References; add for DNSBL).

PowerShell / CLI
- [x] Ensure warnings from RPKI do not surface as terminating errors in PS.
- [x] Add CLI/PS narrative metadata overrides (Title/Subject/Category/Keywords/Creator); wire to Word/HTML composition.

Docs
- [x] Remove “Report Settings” references from README/docs; note that Generated timestamp is in header and domain count appears in Executive Summary → Overview.
- [x] Document Mail Classification scoring (ranges, common signals, example breakdown) and link from the report blurb.

Tests & QA
- [ ] Add Pester test: RPKI 5xx downgraded to Warning; pipeline continues; assessments include `RPKI.Query.Failed` with Warning severity.
- [ ] Add Pester test: composed Word report contains headings “Executive Summary”, “Overview”, “All References” (with lead text), and Consolidated Recommendations has a “Domains” column.
- [ ] Golden report pass: single‑domain and multi‑domain; verify all sections show one‑liner intros and References blocks.

Backlog (not tomorrow)
- [ ] HTML parity follows once HtmlForgeX updates land; keep section structure identical to Word.

## Reports (Word/HTML)
- SPF Word: Add small “Good Posture” iconography or subtle styling to Positives list (optional).
- DMARC/DKIM Word: Implement reports reusing WordReportCommon helpers; include “Good Posture” and actionable Recommendations. [done]
- HTML: Surface “Good Posture” cards/section (start with SPF, then DMARC/DKIM) using view.Positions and narrative.Positives.
- Footer helper: Add WordReportCommon.AddFooter(doc, left, right) with invisible table; left defaults to CompanyLine when present, else Confidential. [done]

## Narratives & Metadata
- Confirm Title/Subtitle/Category/Keywords/Creator for all future narratives (DMARC/DKIM done; extend to others when needed).
- Document narrative metadata contract so PS/CLI and Word/HTML stay in sync.

## Views (Recommendations vs Positives)
- Completed: Most converters now use RecommendationEngine.FromProblems(...) and expose Positives = FromPositives(...).
- Follow‑ups:
  - EDNS: Assign Positives in EdnsSupportSummary (property added; not yet assigned). [done]
  - Sweep all converters to ensure BuildReferences uses the filtered `recs` variable (some already updated). [done: EDNS, Apex, FCrDNS, MailLatency, DMARC]
  - DomainOverall: Consider an aggregated Positives rollup (Info-only view), or leave at RecommendationView for now.

## PowerShell / CLI Options
- Add CLI flags and PS Set-DDExportOptions fields to override narrative metadata (Title/Subject/Category/Keywords/Creator) per run; default to narrative values.
- Expose company branding at CLI level and ensure ApplyCompanyBranding is called for all Word reports.
- Consider `-ShowPositives` switch for table views (PS) to quickly list posture signals.

## Office/Word Plumbing
- WordReportCommon: Add AddFooter helper; ensure invisible borders for header/footer tables consistently.
- Watermark: Optionally apply uniformly to all sections/headers.
- CustomDocumentProperties: Add a light validation to ensure properties appear in File > Info.

## Docs & Examples
- Update Docs/REPORTS.MD and examples to show:
  - $view.Recommendations (fixes) vs $view.Positives (good posture).
  - Narrative.Highlights vs Narrative.Positives/Remediations.
  - Word/HTML examples including company branding and Good Posture section.

## Tests & QA
- Snapshot tests for Views to assert Recommendations exclude Info and Positives include only Info.
- SPF/DMARC/DKIM: Verify positive Info codes are emitted consistently and appear in Positives.
- Pester tests for PS flows (export switches, branding, open‑in‑browser); confirm no pipeline flooding.

## Provider Follow‑ups
- Expand positive posture codes where missing:
  - DMARC: add “rua present”, “ruf present”, “strict alignment” (already mapped), sanity for ri/pct.
  - DKIM: ensure “sha256 present”, “canonicalization valid”, “key type valid” are surfaced per selector.
  - HTTP: keep existing Info positives; ensure mappings cover HSTS/CSP/Referrer‑Policy etc.
- MX/NS/DNSSEC/RPKI: add Info‑level positives where meaningful (e.g., diverse NS, DS/chain valid, all ROAs valid).

## Performance / UX
- Ensure RecommendationEngine.FromProblems/FromPositives calls are inexpensive (they reuse GroupByCode; acceptable for typical sizes).
- Consider caching GroupByCode results within a converter when used multiple times.

## Nice‑to‑have
- Add Positives/Remediations blocks to DomainOverall, with counts and sample items.
- HTML sticky TOC and small charts (severity/mechanism) parity across reports.

---

Pick‑up order (suggested):
1) Finish EDNS Positives assignment + sweep BuildReferences(recs). (EDNS positives done; refs sweep partial)
2) Add Word footer helper; set left = CompanyLine when available. [done]
3) DMARC/DKIM Word reports (Good Posture + Recommendations).
4) HTML “Good Posture” for SPF. [done]
5) CLI/PS overrides for narrative metadata; doc updates; quick tests.

