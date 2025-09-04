# Reporting Architecture and Style Guide

## Goals
- Reusable, format-agnostic report structure for specific areas (SPF, DMARC, DKIM, MX, DNSSEC, TLS, MTA-STS, DANE, HTTP, DNSBL) and aggregate (single- and multi-domain) reports.
- Consistent content: Summary, Findings (assessments), Actions (recommendations), Evidence (tables, samples), with numbering (1, 1.1, 1.1.1).
- Word and HTML as primary targets; PDF to follow, Excel for data-first exports.

## Structure
- Cover: title, logo (optional), generated at, author.
- TOC: auto-generated from headings.
- Sections: top-level per domain; within each domain, per-area sections.
- Numbering: H1 → 1, H2 → 1.1, H3 → 1.1.1.

## Area Template
For each area (e.g., SPF):
1. Area Title (e.g., "SPF Assessment for <domain>")
1.1 Summary: KPIs, grade, key facts.
1.2 Findings: table of coded assessments (Severity, Code, Target, Message, Timestamp).
1.3 Actions: prioritized recommendations (Title, Why, How, Effort, Verify).
1.4 Evidence: records, configuration details, resolved data, samples.

### SPF – Required Sections (detailed)
- Introduction: what SPF is and its role in anti‑spoofing.
- Why it matters: business context and risk framing.
- Summary: record present, starts with v=spf1, all= qualifier, DNS lookups used, unknown mechanisms.
- Findings: all assessments (Info/Warning/Error), not only warnings.
- Mechanisms: table listing qualifier, type (a/mx/ip4/…), value, inferred provider.
- DNS Lookups: distinct domains looked up during evaluation.
- Flattened IP Analysis:
  - Unique IPs count; Duplicate IPs count; Tokens resolved count.
  - Token→IPs counts table; sample of unique IPs (first N).
  - Flattened SPF tree (optional appendix).
- Policy Checks: CycleDetected, CyclePath, Advisory string.
- Recommendations: table with Code, Title, How (plus Why/Effort if space allows).
- References: RFC 7208 and vendor best practices.

We will mirror this pattern for DMARC and DKIM (with policy semantics, alignment, selectors, keys, reports) and for other providers, capturing both technical evidence and management-level context.

## Visuals
- Word: headings, tables, optional charts, callouts; header/footer branding; optional watermark.
- HTML: Tabler-based layout, infocards, Chart.js, anchor-based TOC; dashboard and document templates.

## Configuration
- Template: Executive, Technical, Compliance, Dashboard.
- Theme: Light, Dark, Professional.
- Branding: LogoPath, HeaderText, FooterText, WatermarkText.

## Implementation Plan
1. Build a thin internal IR (Document, Section, Paragraph, Table, Chart) and a numbering helper.
2. Implement SPF report (Word + HTML) using area builder and renderers.
3. Extend to DMARC + DKIM; create aggregate report that composes area outputs.
4. Add multi-domain aggregation (portfolio summary matrix + per-domain sections).
5. Mirror in HTML (document + dashboard templates). Add PDF via QuestPDF or HTML→PDF later.

## Notes
- Reports should be consumable artifacts, not live UI only; dashboards provide interactive view.
- Keep JSON artifacts as the canonical data source; reports summarize and narrate.
