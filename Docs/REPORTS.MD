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

## Narrative metadata contract

Composition-based reports accept a consistent set of narrative metadata fields and a narrative placement flag.
PowerShell can set defaults via `Set-DDExportOptions`. CLI or SDK calls can pass overrides where supported.

Metadata fields:

| Field | Description | Notes |
|---|---|---|
| Title | Report title override | Used for document title and HTML title. |
| Subject | Report subject/description | Used in document properties and HTML description. |
| Category | Report category | Stored as document metadata. |
| Keywords | Report keywords | Comma-separated list for document metadata. |
| Creator | Report author/creator | Used in document properties and headers where supported. |

Narrative placement (`NarrativePlacement`):

- `Auto`: Use a global background section for multi-domain reports, otherwise embed narratives per domain.
- `Global`: Render a single background section with narratives and omit per-domain narratives.
- `PerDomain`: Render narrative sub-sections inside each per-domain section.
- `None`: Disable narrative sub-sections entirely.

## Implementation Plan
1. Build a thin internal IR (Document, Section, Paragraph, Table, Chart) and a numbering helper.
2. Implement SPF report (Word + HTML) using area builder and renderers.
3. Extend to DMARC + DKIM; create aggregate report that composes area outputs.
4. Add multi-domain aggregation (portfolio summary matrix + per-domain sections).
5. Mirror in HTML (document + dashboard templates). Add PDF via QuestPDF or HTML→PDF later.

## Notes
- Reports should be consumable artifacts, not live UI only; dashboards provide interactive view.
- Keep JSON artifacts as the canonical data source; reports summarize and narrate.

## Mail Classification Scoring

The Mail Classification section summarizes whether a domain sends and/or receives mail and explains the confidence. The classifier aggregates lightweight signals with simple weights to compute a score and confidence, then assigns a category.

### Signals and Weights

| Signal | Weight |
|---|---:|
| HasMX (valid MX, not null/localhost) | +2.0 |
| HasNullMX | −5.0 |
| HasAorAAAA (fallback address present) | +0.5 |
| EffectiveSPFSends | +2.0 |
| HasDKIM | +2.0 |
| HasMTASTS | +1.0 |
| HasTLSRPT | +0.5 |
| HasDANE (SMTP) | +0.5 |
| HasBIMI | +1.0 |
| HasBIMI_VMC (valid VMC) | +0.5 |
| AsnDiversity (≥3 ASNs → +1.0; 2 ASNs → +0.5) | +1.0 / +0.5 |

Sending score = EffectiveSPFSends + HasDKIM + HasBIMI + HasBIMI_VMC.

Receiving score = HasMX + HasMTASTS + HasTLSRPT + HasDANE + HasAorAAAA + AsnDiversity.

Total score = sum of all signal weights (including Null MX penalty when present).

### Categories and Confidence

- Parked: Null MX present and no sending signals → High confidence.
- Sending & Receiving: at least one receiving signal and one sending signal.
  - Confidence High when Receiving score ≥ 2.0 AND Sending score ≥ 3.0; else Medium.
- Receiving Only: receiving signals present, no sending signals → Medium confidence.
- Sending Only: sending signals present, no receiving signals →
  - Confidence High when Null MX present; otherwise Medium.

### Example Breakdown

For a domain with MX, SPF (effective), DKIM, TLS-RPT:

| Key | Points |
|---|---:|
| HasMX | 2.0 |
| EffectiveSPFSends | 2.0 |
| HasDKIM | 2.0 |
| HasTLSRPT | 0.5 |
| Total | 6.5 |

Classification: Sending & Receiving; Confidence: High (receiving ≥ 2.0 and sending ≥ 3.0).

The report includes a brief “Scoring rubric” and a “Signals considered” list. When one list (Sending/Receiving) is empty, it renders as “None”.
