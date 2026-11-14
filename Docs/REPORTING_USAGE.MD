# DomainDetective Reporting - Usage Guide

## Quick Start

### C# Library Usage

```csharp
// Basic usage: the assessment report for every check the run executed
var healthCheck = new DomainHealthCheck();
await healthCheck.Verify("example.com");

var items = DomainDetective.Views.Converters.ConvertChecks(healthCheck);
AssessmentHtmlReport.Generate("report.html", items, openInBrowser: true);

// The same model as JSON
var assessment = DomainAssessmentBuilder.Build(items);
File.WriteAllText("report.json", DomainAssessmentJson.Serialize(assessment));
```

### CLI Usage

```bash
# Generate HTML report
ddcli report example.com

# Choose the format and output path; HTML uses the assessment layout
ddcli report example.com --format html --output assessment_report.html

# Export Word and PDF from the same document build
ddcli report example.com --format word,pdf --output ./Reports/assessment.docx

# Repeated format flags; the explicit theme applies to HTML
ddcli report example.com --format html --format pdf --theme dark --output ./Reports/assessment.html

# Include discovery add-ons (can be slow)
ddcli report example.com --dns-trace --dns-propagation

# List and open recent artifact runs
ddcli RunsList --subject example.com --count 5
ddcli RunsOpen --subject example.com

# Each report command analyzes one domain; combine report formats in that run
ddcli report example.com --format html,word,pdf
```

### PowerShell Usage

```powershell
# Basic HTML report
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Html

# HTML report with custom path
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Html -ExportPath "C:\Reports\exec_report.html"

# Compose an assessment report from the checks in the block
Export-DDSecurityReport -ExportFormat Html -ExportPath ".\\assessment.html" {
    Test-DDDomainOverallHealth -DomainName "example.com"
}

# Return a View with Raw included; then export separately
$view = Test-DDDomainOverallHealth -DomainName "example.com"
# Access raw analysis if needed
$health = $view.Raw
$null = Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Html -ExportPath "report.html" -OpenInBrowser

# Batch reporting
@("example.com", "test.com") | ForEach-Object {
    Test-DDDomainOverallHealth -DomainName $_ -ExportFormat Html -ExportPath "reports\$_.html" -OpenInBrowser:$false
}

# Export to different formats
# JSON (implemented)
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Json -ExportPath "data.json"
# Word/PDF/Excel/Markdown from the assessment model
Export-DDSecurityReport -ExportFormat Word,Pdf -ExportPath "report.docx" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}
Export-DDSecurityReport -ExportFormat Excel -ExportPath "report.xlsx" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}

Export-DDSecurityReport -ExportFormat Markdown -ExportPath "report.md" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}
# PDF as the only requested format
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Pdf

```

## Report Types

### 1. HTML reports
- Assessment verdict, priorities, coverage and per-domain checks
- Offline styles and scripts, with system/light/dark themes

### 2. Word and PDF reports
- The same paper assessment document: cover, verdict, priorities, area table and per-domain chapters
- An appendix with all checks, scoring notes and raw records
- PDF conversion through OfficeIMO, including table-of-contents page numbers
- Combined Word/PDF exports build the document once

### 3. Excel reports
- Summary, Do these first, Checks and Findings sheets
- One evidence sheet per check type with table evidence
- Outcome colours use text rather than fills; no merged cells

### 4. Markdown and MarkdownHtml reports
- Verdict, numbered priorities, area table and per-domain checks
- Markdown includes collapsible details; MarkdownHtml also writes the Markdown sidecar

With combined output, a supplied file path provides the base name and each format receives its own extension.
Use `--format word,pdf` or repeated `--format` flags in the CLI, and `-ExportFormat Word,Pdf` in PowerShell.
There is no standalone PDF switch. A failed member does not remove successful reports; the CLI returns failure
if any requested report fails.
In a multi-format batch, MarkdownHtml uses `<base>.markdown.html` with a `<base>.markdown.md` sidecar,
leaving `<base>.html` and `<base>.md` for HTML and Markdown. Single-format filenames are unchanged.
For example, `--format html,pdf,markdown,markdownhtml --output ./Reports/assessment.html` writes
`assessment.html`, `assessment.pdf`, `assessment.md`, `assessment.markdown.html` and `assessment.markdown.md`.

## Artifacts

- Emitted under `./artifacts/<subject>/<timestamp>/` when using coordinated runs.
- Files include:
  - `scan.json`: envelope with metadata, summary, assessments, recommendations, and full `DomainHealthCheck`.
  - `metrics.json`: counters and timing.
  - `progress.jsonl`: JSON lines stream of progress and messages.
  - `index.jsonl`: subject-level index with one line per run.

Use `RunsList` and `RunsOpen` to discover and open recent runs from the index.

## HTML Layout and Compatibility

Every HTML report uses the assessment layout: summary, coverage matrix, filterable checks and domain sections.
The report follows the viewer's light or dark theme by default.

The CLI accepts only `--template default`; other templates are rejected before analysis. PowerShell's
`-HtmlProfile Document` and `-HtmlProfile Dashboard` values are also accepted for compatibility and render the
assessment report with the same default theme behavior.

## Scoring System

Completed checks receive scores based on their findings. Incomplete checks retain their known evidence and
findings without receiving a passing score; area, domain and overall grades are withheld while scored evidence
is incomplete. Inventory and discovery checks are visible but do not contribute to the score.

See [assessment scoring](../DomainDetective.Reports.Html/README.md#scoring) for weights, penalties and grade thresholds.

## Advanced Usage

### Custom Report Options

```csharp
var items = DomainDetective.Views.Converters.ConvertChecks(healthCheck);
var options = new DomainAssessmentOptions { Title = "Domain security assessment" };
var htmlOptions = new AssessmentHtmlOptions {
    Theme = HtmlForgeX.ThemeMode.System,
    ShowInfoFindings = true
};
AssessmentHtmlReport.Generate("report.html", items, options, htmlOptions);
```

### Batch Processing with Progress

```csharp
var domains = new[] { "example.com", "test.com", "demo.com" };
var reports = new List<ReportResult>();

foreach (var domain in domains) {
    Console.WriteLine($"Processing {domain}...");
    
    var hc = new DomainHealthCheck();
    await hc.Verify(domain);
    
    AssessmentHtmlReport.Generate($"reports/{domain}.html", Converters.ConvertChecks(hc));
    
    reports.Add(new ReportResult { 
        Success = true, 
        FilePath = $"reports/{domain}.html" 
    });
}

Console.WriteLine($"Generated {reports.Count} reports.");
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Generate Security Report
  run: |
    ddcli report ${{ vars.DOMAIN }} --format html --output report.html
    
- name: Upload Report
  uses: actions/upload-artifact@v7
  with:
    name: security-report
    path: report.html
```

## Customization

Use `DomainAssessmentOptions` for the report title and domain order, and `AssessmentHtmlOptions` for the
brand, subtitle, theme and informational finding visibility. These options retain the assessment layout and
its evidence-based scoring.

## Examples

See [ReportingHtmlExample.cs](../DomainDetective.Example/ReportingHtmlExample.cs) for HTML and JSON generation
through the assessment model, and the [HTML reports guide](../DomainDetective.Reports.Html/README.md) for options
and scoring rules.

## Troubleshooting

### Common Issues

1. **Report not opening in browser**
   - Check default browser settings
   - Use `OpenInBrowser = false` and open manually

2. **Missing data in report**
   - Ensure all health checks completed successfully
   - Check for DNS resolution issues
   - Verify domain accessibility

3. **Styling issues**
   - HTML assessment reports embed their assets for offline viewing
   - Check browser console errors if an exported file does not render

### Debug Mode

```csharp
// Enable verbose logging
var healthCheck = new DomainHealthCheck { Verbose = true };

// Check individual analysis results
if (healthCheck.SpfAnalysis?.Valid != true) {
    Console.WriteLine($"SPF Issues: {healthCheck.SpfAnalysis?.Issues}");
}
```

## Future Enhancements

- **Real-time monitoring** - Live dashboard updates
- **Historical tracking** - Trend analysis over time
- **Multi-domain comparison** - Side-by-side analysis
- **API integration** - REST API for report generation
- **Scheduled reports** - Automated periodic reporting
- **Custom branding** - White-label support
