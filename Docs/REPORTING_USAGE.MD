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

# Generate without opening browser
ddcli report example.com --no-open

# Include discovery add-ons (can be slow)
ddcli report example.com --dns-trace --dns-propagation

# List and open recent artifact runs
ddcli RunsList --subject example.com --count 5
ddcli RunsOpen --subject example.com

# Batch processing
ddcli report example.com,test.com,demo.com --format html
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
# Word/Excel/Markdown via composition (Excel requires .NET 8.0+ or net472 on Windows)
Export-DDSecurityReport -ExportFormat Word -ExportPath "report.docx" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}
Export-DDSecurityReport -ExportFormat Excel -ExportPath "report.xlsx" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}

# Excel dashboard profile (single overview + dashboard sheet)
Export-DDSecurityReport -ExportFormat Excel -ExcelProfile Dashboard -ExportPath "dashboard.xlsx" {
    Test-DDDomainOverallHealth -DomainName "example.com"
}

Export-DDSecurityReport -ExportFormat Markdown -ExportPath "report.md" {
    Test-DDEmailSpfRecord -DomainName "example.com"
    Test-DDEmailDmarcRecord -DomainName "example.com"
}
# PDF (planned)
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Pdf

# Protocol-specific exports (TODO)
# You can request export on specific tests; dedicated reports will be added.
Test-DDEmailSpfRecord -DomainName "example.com" -ExportFormat Html   # TODO: report not yet implemented
Test-DDEmailDmarcRecord -DomainName "example.com" -ExportFormat Html # TODO: report not yet implemented
```

## Report Types

### 1. HTML Reports (Available)
- Interactive dashboard with charts
- Responsive design for mobile/desktop
- Export capabilities (PDF, Excel from browser)
- Real-time score calculations

### 2. Word Reports (Available)
- Professional document format
- Executive summary and per-domain sections
- Print-ready formatting

### 3. Excel Reports (Available)
- Overview + per-domain sheets (composition-based)
- Pivot table ready data grid
- Multiple worksheets for categories (where applicable)
### 4. Markdown Reports (Available)
- Document-style layout mirroring Word
- Executive summary + per-domain sections

### 5. PDF Reports (Planned)
- Print-optimized layout
- Compliance documentation
- Digital signatures support
- Archive-ready format

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

The CLI accepts `--template` for compatibility; it does not select another HTML layout. PowerShell's
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
   - Reports require internet for CDN resources
   - Use offline mode for air-gapped environments

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
