# HTML Reporting Modernization Plan

Goal: Make HTML reports match (or surpass) the maturity of Word reports and TestimoX-style dashboards.

## Phase 1 - Dashboard-first summary (now)
- [x] Add KPI header row with grade/status and warning/error counts
- [x] Add Top Findings rollup (aggregated across domains)
- [x] Add Control Risk Rollup (OK/Warn/Error per control)
- [x] Keep Executive Summary table canonical, but move it below dashboard cards

## Phase 2 - Per-domain maturity (next)
- [x] Domain card header: status badge, counts, provider chain
- [x] Domain quick stats grid (MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/RPKI)
- [x] Domain Top Findings card (top 3-5 warnings/errors)
- [x] Section layout: Summary grid + Findings + Evidence + References blocks
- [x] Security rating hero: grade badge + inbound/outbound posture + key status chips
- [x] Evidence blocks per section (raw DNS, headers, TLS chain, etc.)
- [x] Evidence blocks for SPF/DMARC/DKIM/MTA-STS/TLS-RPT

## Phase 3 - Evidence + UX parity
- [x] Evidence panels (raw DNS records, headers, TLS chain, etc.)
- [ ] Resolver matrix for DNS-heavy sections
- [x] Provider trust grid (DNSBL/reputation)
- [x] Sticky TOC / ScrollSpy for large reports (optional)

## Phase 4 - Visual polish & consistency
- [x] Unified status palette (OK/Warning/Error) across all widgets
- [ ] Card spacing and typography pass (Tabler layout polish)
- [ ] Align HTML narrative one-liners with Word content

## Guidance & Narration Parity (TestimoX-inspired)
- [ ] Introduce a narrative registry (per check/category) that maps to `NarrativeSections`
- [ ] Expand narratives for core categories (MX/SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC/RPKI/ARC/BIMI)
- [x] Render narrative blocks in HTML: Summary, Why It Matters, How To Fix, References
- [ ] Surface guidance in Word/Markdown using the same narrative source
- [ ] Add per-check “best practice” hints derived from guidance + assessments
- [ ] Add optional “Evidence” sub-blocks tied to guidance (record samples, recommended values)

## Implementation Notes
- Base patterns from:
  - HtmlForgeX.Examples/Reports/DomainComplianceReport.cs
  - TestimoX/Reporting/Html/HtmlReports.TopSummary.cs
- Guidance patterns from:
  - TestimoX/Rules/** (RuleBuilder.WithGuidance: Summary / Why / How / References)
- Keep HTML profile split: Document (narrative) vs Dashboard (KPI-first).

---
Progress log
- 2025-12-19: Added plan; starting Phase 1 implementation.
- 2025-12-19: Added Top Findings + Control Risk rollups; per-domain quick stats + top findings card.
- 2025-12-19: Added provider chain line to per-domain summary.
- 2025-12-19: Added security rating hero + guidance/evidence blocks for SPF/DMARC/DKIM/MTA-STS/TLS-RPT.
- 2025-12-19: Added narrative guidance blocks across MX/ARC/BIMI/DNSBL/DNSSEC/RPKI/NS/SOA/CAA/DANE/Wildcard/Zone Transfer/Classification.
- 2025-12-19: Added evidence blocks for MX/DNSBL/NS/SOA/CAA/DNSSEC/DANE/RPKI/Zone Transfer/Wildcard/Classification.
- 2025-12-19: Added evidence blocks for ARC/BIMI/Mail TLS (headers, VMC cert, TLS server details).
- 2025-12-19: Added KPI header row with grade/status badges; confirmed executive summary placement.
- 2025-12-19: Added control coverage summary in executive dashboard.
- 2025-12-19: Added Markdown per-domain guidance/evidence parity and mail TLS evidence tables.
- 2025-12-19: Added Excel Overview provider chain table.
- 2025-12-19: Added DNSBL provider trust grid and Mail TLS narrative blocks.
- 2025-12-19: Unified status badge palette and added DKIM selector count hint.
- 2025-12-19: Added multi-domain ScrollSpy navigation (sticky TOC) for large reports.
