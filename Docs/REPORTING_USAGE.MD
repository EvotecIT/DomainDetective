# DomainDetective Reporting - Usage Guide

## Quick Start

### C# Library Usage

```csharp
// Basic usage
var healthCheck = new DomainHealthCheck();
await healthCheck.Verify("example.com");

var report = new DomainSecurityReport(healthCheck, "example.com");
report.GenerateReport("report.html", openInBrowser: true);
```

### CLI Usage

```bash
# Generate HTML report
ddcli report example.com

# Generate with specific format and template
ddcli report example.com --format html --template executive --output executive_report.html

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

# HTML dashboard profile (compact KPIs + grids)
Export-DDSecurityReport -ExportFormat Html -HtmlProfile Dashboard -ExportPath ".\\dashboard.html" {
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

## Templates

### Default Template
- Comprehensive overview
- All security checks visible
- Technical details included
- Suitable for IT teams

### Executive Template
- High-level summary
- Focus on business impact
- Risk assessment
- Action items only

### Technical Template
- Detailed analysis
- Configuration examples
- RFC references
- Implementation guides

### Compliance Template
- Regulatory focus
- Audit trail
- Evidence collection
- Policy compliance

## Scoring System

The security score is calculated based on weighted criteria:

| Category | Weight | Checks |
|----------|--------|--------|
| **Impersonation** (35%) | | SPF (10pts), DMARC (15pts), DKIM (10pts) |
| **Privacy** (30%) | | TLS (15pts), MTA-STS (10pts), DANE (5pts) |
| **Infrastructure** (25%) | | DNSSEC (10pts), NS (5pts), MX (5pts), CAA (5pts) |
| **Branding** (10%) | | BIMI (5pts), Certificate (5pts) |

### Risk Levels
- **80-100**: Low Risk 🟢
- **60-79**: Medium Risk 🟡
- **40-59**: High Risk 🟠
- **0-39**: Critical Risk 🔴

## Advanced Usage

### Custom Report Options

```csharp
var options = new ReportOptions {
    Title = "Security Audit - Q4 2024",
    TemplateName = "Executive",
    Theme = ReportTheme.Professional,
    IncludeTechnicalDetails = false,
    IncludeRecommendations = true,
    CustomProperties = new Dictionary<string, object> {
        ["CompanyLogo"] = "/path/to/logo.png",
        ["ShowHistoricalData"] = true,
        ["ComparisonDomains"] = new[] { "competitor1.com", "competitor2.com" }
    }
};

// Future API
var generator = new HtmlReportGenerator();
var result = await generator.GenerateAsync(healthCheck, options);
```

### Batch Processing with Progress

```csharp
var domains = new[] { "example.com", "test.com", "demo.com" };
var reports = new List<ReportResult>();

foreach (var domain in domains) {
    Console.WriteLine($"Processing {domain}...");
    
    var hc = new DomainHealthCheck();
    await hc.Verify(domain);
    
    var report = new DomainSecurityReport(hc, domain);
    report.GenerateReport($"reports/{domain}.html", false);
    
    reports.Add(new ReportResult { 
        Success = true, 
        FilePath = $"reports/{domain}.html" 
    });
}

// Generate summary report
GenerateSummaryReport(reports);
```

### Integration with CI/CD

```yaml
# GitHub Actions example
- name: Generate Security Report
  run: |
    ddcli report ${{ vars.DOMAIN }} --format html --output report.html
    
- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: report.html
```

## Customization

### Custom Templates (Coming Soon)

```csharp
public class CustomTemplate : IHtmlTemplate {
    public string Name => "Custom";
    
    public void Render(TagPage page, SecurityScore score) {
        // Custom rendering logic
    }
}

// Register custom template
ReportTemplateRegistry.Register(new CustomTemplate());
```

### Custom Scoring Rules

```csharp
public class CustomScoringEngine : IScoringEngine {
    public SecurityScore Calculate(DomainHealthCheck healthCheck) {
        // Custom scoring logic
        return new SecurityScore {
            OverallScore = CalculateCustomScore(healthCheck)
        };
    }
}
```

## Examples

See the `DomainDetective.Example` project for complete examples:

- `ExampleHtmlReport.cs` - Basic HTML report generation
- `ExampleBatchReporting.cs` - Batch processing multiple domains
- `ExampleCustomTemplate.cs` - Creating custom report templates
- `ExampleScoringSystem.cs` - Understanding the scoring algorithm

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
