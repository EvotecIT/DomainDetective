# Domain assessment export layouts: Word, PDF, Excel and Markdown

Layout and behavior of the domain assessment exports. Tests and fixtures use made-up data only.

Standalone ARC and message-header inputs use the message evidence renderers for Word, PDF, Excel, Markdown and HTML. They retain header structure and findings without treating them as domain assessments or cryptographic verification. Export message evidence separately from domain views. JSON through this composition route returns an unsupported-format result; the original analysis remains the JSON source.

## 0. Rules for every export

- **One model, one vocabulary.** Every export reads the same `DomainAssessmentReport` as the HTML report, never the legacy `SectionProjectors`/`Composition`.
  - Every sentence the HTML shows comes from one place: the verdict, the "Do these first" lines, area lines, outcome labels and "Not scored" states.
  - `AssessmentReportWording` in `DomainDetective.Reports` supplies verdicts, area notes, outcome labels, priorities and score notes to every renderer.
- **Same states as the HTML:**
  - Error is high (red).
  - Warning is elevated (amber).
  - A check that couldn't run (a lookup or probe that failed) is "Couldn't check" in neutral grey, never amber. It is never a thing to fix and never counts as a warning.
  - Area and domain scores count the checks that could be judged and show the share they rest on ("83% of checks judged"). Only an area where nothing could be judged says "Not scored".
  - Pass is green. Zero figures are muted, not green.
- **Paper style:** OfficeIMO `WordPaperStyle`. Defaults: Aptos / Aptos Display, ink 202428, hairline tables. Accent: the report's teal (0F766E) for the cover rule and eyebrows only. Status colours come from the same semantic tones as the HTML report.
- **Typography:** body 10.5 pt; tables 9 pt; identifiers (hostnames, record values, codes) in a monospace face, wrapped with `WordPaperText` identifier wrapping so they break at dots and hyphens, not mid-label.
- **Page:** A4 portrait by default (Letter by culture or option); 18 mm margins. Footer: product, report title, page "n of m". Header from page 2 on: domain(s) and generated time.
- **Print-only truth:** an export never says "click", "open" or "show more". Long lists print in full or say exactly what was left out and where it is ("first 25 shown; all 112 in the XLSX").
- **Sizes:** a compact one-domain DD Word report should be about 4–6 pages (without a dedicated contents page); 24 domains should stay under about 60 pages, with the appendix carrying the long tables.

## 1. DD Word (and PDF from it)

PDF is a public export: the same document converted through OfficeIMO's Word-to-PDF path, with correct TOC page numbers. PowerShell takes `Pdf` the way it already takes the other formats (a `-Pdf` switch or a `Pdf` value in the existing format parameter, whichever pattern the cmdlet uses); the CLI takes `--format pdf`. When Word and PDF are both requested, the document is built once and converted.

OfficeIMO 3.6.1 has two layout limitations: refreshing Contents in native Word can leave the cached entries beside the refreshed list, and PDF keep-with-next can leave a heading before a table that starts on the following page. The shared fixes are [OfficeIMO #3477](https://github.com/EvotecIT/OfficeIMO/pull/3477) and [#3491](https://github.com/EvotecIT/OfficeIMO/pull/3491); they are consumed through normal dependency updates.

Order:

1. **Cover (page 1, no header).**
   - `AddCover`: eyebrow "Domain assessment", title = the domain (or "24 domains"), subtitle = "Generated 2026-10-21 17:32 UTC · 84 checks in 5 areas".
   - Under it, a verdict block: the one-sentence verdict (shared wording, e.g. "Both domains have errors.") and the detail line.
   - Then a metric strip of four `ApplyValueCard` cards:
     - Grade/score, or "Not scored" muted;
     - Checks needing attention (elevated or high tone);
     - Errors (high when > 0, muted at 0);
     - Incomplete evidence (neutral).
2. **Contents (several domains).**
   - Immediately after the summary tiles, headed "Contents" in the H2 style, without a forced page break. A single-domain report skips the contents list.
   - Entries point to Summary, the domain chapters and appendix, with final PDF page numbers. Summary covers Do these first, Area by area and Controls.
3. **Do these first.**
   - Identical check/finding pairs are grouped across domains, ordered by severity and then affected-domain count. Up to `FixFirstCount` (default 10) grouped items appear, in the same order as the HTML.
   - Each item: bold check title, one muted metadata line with the affected domains (`All 24 domains · Mail` or a count and list), then the top finding message. Keep the status word in its tone in the left column, with about 6 pt between items. Only identifiers use monospace.
   - Rendered as a two-column table: status in a narrow left column, text on the right. No cards.
4. **Area by area.**
   - One table row per area: Area, Status, Score (or "Not scored"), Checks, Passing, Needs attention.
   - Passing counts include only scored checks with a Pass outcome. Informational checks remain in Checks and their evidence stays available.
   - Then the area line (shared wording) as a muted row below each area.
5. **Controls** (multi-domain only).
   - A matrix table: domains as rows, controls as columns (DMARC, SPF, DKIM, MX, MTA-STS, TLS-RPT, BIMI, DNSSEC, CAA, plus every scored Web and Security check present, including Certificate).
   - At most six controls per table, repeating the domain column to keep full status words readable on portrait pages. Every group uses the same domain and status column widths, reserving unused columns in the last group.
   - Cells "Pass", "Warning", "Error", "–" with tone text, not fills (paper prints in grey too). The dash explanation appears only when the matrix contains a dash.
6. **One chapter per domain** (a page break before each).
   - Chapter heading: domain, grade, score.
   - A metric strip with the domain's per-area scores ("Not scored" muted where incomplete).
   - Then per area, one table of its checks: Check, Outcome (tone text), Key number, Top finding. Rows with an outcome other than pass first.
   - Each check that needs attention gets a short block under the table:
     - its findings (all warnings and errors);
     - "What to do" (recommendation title plus how);
     - the evidence as a `AddKeyValueTable` (the same facts the HTML drawer shows), keeping the presentation map and "Not attributed" rules.
   - Passing checks get no block, only their row.
7. **Appendix.**
   - "All checks": one table, every domain × check, ordered by Mail, DNS, Web, Security and Other within each domain; the Explore columns except the redundant "Key numbers" column (retained in Excel).
   - "How scoring works": the same facts as the HTML About section.
   - Raw records (SPF/DMARC/MTA-STS text) in monospace key-value tables.
   - Captured facts and lists from checks without a detailed block, including informational and passing checks. Hiding informational findings does not hide their evidence.
   - Table evidence up to 12 rows and 9 columns prints in full; a larger table is listed with its size and points to the Excel workbook, which has every row. Long finding and fact lists in the domain chapters say how many were left out the same way.

The opening summary, Contents, Do these first, Area by area and Controls flow together. A one-domain report starts Do these first on page 1. Break before each domain chapter and the appendix; the appendix subsections flow. The score note appears only in How scoring works. Paper-table sizing reserves each header's longest unbreakable word plus padding. Key numbers use the body font.

## 2. DD Excel

One workbook, OfficeIMO.Excel:
- every list is a native Excel table with banded rows and a filter; the header row and identifying columns are frozen;
- outcome cells have a pale fill behind the tone colour (error red, warning amber, pass green, couldn't check grey);
- scores are numbers with a 0–100 data bar; an unscored cell is empty, and the sheet header says why;
- a one-domain workbook names the domain in each sheet title instead of repeating a Domain column;
- column widths are set deliberately and only finding text wraps;
- sheet tabs are coloured by group.

Sheets:

1. **Summary**: the verdict, tiles (score with coverage, needs attention, errors, couldn't check, risk, confidence), the area table with score bars and coverage, the top actions, and an outcome chart.
2. **Do these first**: one row per domain and check for filtering, retaining the shared action wording.
3. **Checks**: one row per domain × check: Domain (several domains only), Area, Check (linked to its evidence), Outcome, Score, and one plain-words "What was found" column.
4. **Findings**: the same columns as the Explore "Findings" dataset.
5. **Evidence**: captured facts, raw records and list items, attributed to their domain and check. Collection-time omissions remain explicit.
   Table evidence (MX hosts, name servers, DKIM selectors and so on) sits on the same sheet, grouped by check under a heading row with collapsible row groups, instead of one sheet per check.
6. **Risk profile**: when a domain has one, its verdict, signals, evidence coverage and facts.

## 3. DD Markdown

For pasting into tickets and wikis:
- `# Domain assessment: <domain(s)>`;
- the verdict sentence;
- "Do these first" as a numbered list with one line per grouped check/finding, ordered by severity and affected-domain count (`1. **Check** (All 24 domains, area, error): finding`); additional finding counts remain in the same line;
- the area table;
- per domain, a table of checks that need attention, then a collapsible `<details>` with all checks.

The same shared wording, no HTML-only phrases. Parentheses and single spaces stay literal; escape only Markdown syntax, using no HTML character references.

## 4. Validation

- Unit tests:
  - the shared wording produces identical sentences in HTML, Word and Markdown for the same model (one parity test);
  - incomplete evidence is never toned as a warning in any export;
  - captured facts, records and lists remain available when informational findings are hidden;
  - CLI `report --format json` retains the raw health-check JSON contract, including when combined with assessment formats.
- Made-up 1-, 3- and 24-domain runs in each format, kept outside the repository for visual review. Native Word field-refresh PDFs are checked alongside the generated exports, with version-specific Contents limitations recorded. HTML Controls use equal-width tiles at 1440, 1024 and 390 px, and grouped actions open Explore with the affected domains and finding selected.
- The legacy `SectionProjectors`/`Composition` Office and Markdown code removed once nothing uses it.
