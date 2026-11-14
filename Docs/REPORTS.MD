# Reporting architecture and exports

Domain assessment reports read `DomainAssessmentReport`. HTML, Word/PDF, Excel and Markdown use the shared `AssessmentReportWording` for verdicts, priority actions, area lines and outcome labels. Exporting completed evidence does not rerun checks. Incomplete evidence remains neutral and unscored.

## Public formats

PowerShell uses its existing `-ExportFormat` array. PDF is available wherever Word is offered, including individual checks, overall domain reports and message-header reports. Formats can be combined:

```powershell
$views | Export-DDSecurityReport -ExportFormat Html,Word,Pdf -ExportPath ./Reports/assessment.html
Test-DDDomainOverallHealth -DomainName example.test -ExportFormat Word,Pdf -ExportPath ./Reports/assessment.docx
Set-DDExportOptions -DefaultFormat Pdf
```

The CLI accepts repeated or comma-separated format values:

```sh
DomainDetective.CLI report example.test --format html,word,pdf --output ./Reports/assessment.html
DomainDetective.CLI GenerateReport example.test --format word --format pdf --output ./Reports/assessment.docx
DomainDetective.CLI DesiredState example.test --desired-state ./desired-state.json --format word,pdf --output ./Reports/desired-state.docx
```

Combined file outputs share the supplied base name and use their format extensions. In a batch, Markdown HTML uses `.markdown.html` and its sidecar uses `.markdown.md`, keeping both distinct from the assessment HTML and standalone Markdown. A Word/PDF request builds one Word document and converts that same document through OfficeIMO's Word-to-PDF engine. PDF has no separate layout. PDF TOC numbers use the converter's final pagination.

## Assessment layout and ownership

The maintained layout is specified in [REPORT_EXPORTS.MD](REPORT_EXPORTS.MD), sections 0–3. Word/PDF contains the cover and verdict, metrics, priority actions, area table, multi-domain controls, one chapter per domain and an appendix. Identifiers use invisible break opportunities at separators, never inserted visible spaces.

Excel provides Summary, Do these first, Checks, Findings and per-check-type table-evidence sheets. Outcome tone uses text colour without fills or merged cells. Markdown provides the verdict, numbered actions, area table, attention checks and collapsible complete checks.

`DomainDetective.Reports` owns the assessment model and wording. `DomainDetective.Reports.Office` owns paper/workbook rendering and the shared Word/PDF batch. `DomainDetective.Reports.Markdown` owns Markdown. HTML uses the same model through `DomainDetective.Reports.Html`. Format entry points stay thin and acquire evidence once.

The assessment layout supports title, domain ordering and informational-finding visibility. Nondefault retired scope, branding, narrative-placement and section-order overrides fail before output; they are not silently applied. See the generated [Export-DDSecurityReport help](../Module/Docs/Export-DDSecurityReport.md).

## Message evidence

Message reports keep receiver authentication claims, identity alignment, route declarations and local cryptographic verification separate. Word and PDF share one message-evidence document; the PDF is its OfficeIMO conversion. Original fields and signature observations remain in the evidence appendix. Message reports do not fetch unsubscribe links or execute header-supplied markup.

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
