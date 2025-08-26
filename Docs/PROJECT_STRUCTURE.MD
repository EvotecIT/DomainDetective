# DomainDetective Project Structure

## Proposed Project Organization

### Core Projects

#### 1. **DomainDetective** (Core Library)
- Domain analysis functionality
- Health checks and protocols
- DMARC/DKIM/SPF analysis
- **Move here**: DmarcForensicParser, DmarcReportParser, DmarcFeedbackSummary
- All core detection and analysis logic

#### 2. **DomainDetective.Reports** (Base Reporting)
- Common reporting interfaces and models
- `IReportGenerator` interface
- `ReportOptions`, `ReportResult`, `ReportFormat` enums
- Shared scoring models
- Base classes for all report generators

#### 3. **DomainDetective.Reports.Html** (HTML Reports)
- References: DomainDetective.Reports, HtmlForgeX
- HTML report generation using HtmlForgeX
- Interactive dashboards and visualizations
- Web-based export functionality

#### 4. **DomainDetective.Reports.Office** (Office Documents)
- References: DomainDetective.Reports, OfficeIMO.Word, ClosedXML
- Word document generation using OfficeIMO.Word
- Excel spreadsheet generation using ClosedXML
- Professional document templates

#### 5. **DomainDetective.Reports.Pdf** (PDF Reports)
- References: DomainDetective.Reports
- PDF generation (using QuestPDF or similar)
- Print-ready reports
- Compliance documentation

### Integration Points

#### CLI Integration
```csharp
// In DomainDetective.CLI
// References: All report projects

var reportFactory = new ReportGeneratorFactory();
reportFactory.Register(new HtmlReportGenerator());
reportFactory.Register(new WordReportGenerator());
reportFactory.Register(new ExcelReportGenerator());

// Usage
var report = await reportFactory.CreateReport(healthCheck, format: ReportFormat.Html);
```

#### PowerShell Integration
```powershell
# In DomainDetective.PowerShell
# References: All report projects

Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Html -Template Executive
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Word -IncludeRawData
Test-DDDomainOverallHealth -DomainName "example.com" -ExportFormat Excel
```

## Benefits of This Structure

1. **Separation of Concerns**
   - Core analysis logic separate from reporting
   - Each report type in its own project
   - Clean dependencies

2. **Flexible Dependencies**
   - Only load what you need
   - CLI/PowerShell can reference all or specific report types
   - Core library stays lightweight

3. **Maintainability**
   - One class/enum per file
   - Clear project boundaries
   - Easy to add new report formats

4. **Extensibility**
   - New report formats just implement IReportGenerator
   - Plugin-style architecture
   - Custom templates per format

## File Organization Example

```
DomainDetective/
├── Protocols/
│   ├── DmarcAnalysis.cs
│   ├── DmarcForensicParser.cs (moved from Reports)
│   └── DmarcReportParser.cs (moved from Reports)
├── Models/
│   └── DmarcFeedbackSummary.cs (moved from Reports)
└── DomainHealthCheck.cs

DomainDetective.Reports/
├── IReportGenerator.cs
├── ReportFormat.cs
├── ReportOptions.cs
├── ReportResult.cs
├── ReportTheme.cs
├── Models/
│   ├── SecurityScore.cs
│   ├── SecurityCategory.cs
│   ├── SecurityCheck.cs
│   ├── SecurityIssue.cs
│   └── SecurityRecommendation.cs
└── Enums/
    ├── SecurityRiskLevel.cs
    ├── CheckStatus.cs
    ├── IssueSeverity.cs
    ├── RecommendationPriority.cs
    └── EffortLevel.cs

DomainDetective.Reports.Html/
├── HtmlReportGenerator.cs
├── Scoring/
│   ├── IScoringEngine.cs
│   └── HtmlScoringEngine.cs
├── Components/
│   ├── ScoreGauge.cs
│   ├── CategoryCard.cs
│   └── CheckResultsTable.cs
└── Templates/
    ├── IHtmlTemplate.cs
    ├── DefaultTemplate.cs
    └── ExecutiveTemplate.cs

DomainDetective.Reports.Office/
├── WordReportGenerator.cs
├── ExcelReportGenerator.cs
├── Word/
│   ├── WordTemplate.cs
│   └── WordComponents.cs
└── Excel/
    ├── ExcelTemplate.cs
    └── ExcelWorksheets.cs
```

## Migration Steps

1. Move DMARC parsing classes to DomainDetective core
2. Create DomainDetective.Reports base project
3. Create separate projects for each report type
4. Update references in CLI and PowerShell
5. Implement factory pattern for report generation

This structure provides clean separation while maintaining flexibility for different output formats!