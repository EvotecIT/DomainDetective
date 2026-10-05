# DomainDetective HTML Reports

HTML report generation for DomainDetective using HtmlForgeX.

## Assessment report

The assessment report is a single offline HTML file with:

- a summary: overall score and grade, scores per area (Mail, DNS, Web, ...), and what to fix first;
- a coverage matrix of every check across every domain (when more than one domain is assessed);
- one section per domain with every check that ran: outcome, findings, what the domain does well, how to fix it,
  and the evidence behind the result (raw records, facts and tables).

```csharp
var healthCheck = new DomainHealthCheck();
await healthCheck.Verify("example.com");

// Views for every check the run executed.
var items = DomainDetective.Views.Converters.ConvertChecks(healthCheck);

// Build and render in one step...
AssessmentHtmlReport.Generate("report.html", items);

// ...or build the model once and render it as HTML and JSON.
DomainAssessmentReport assessment = DomainAssessmentBuilder.Build(items);
AssessmentHtmlReport.Generate("report.html", assessment, new AssessmentHtmlOptions { Theme = ThemeMode.Dark });
File.WriteAllText("report.json", DomainAssessmentJson.Serialize(assessment));
```

`AssessmentHtmlOptions` controls the brand, subtitle, theme (system by default), library mode (offline by default) and
whether informational findings are shown.

### Scoring

- Check score: 100 when a check passes, 15 points off per warning (not below 50), 40 with one error and 10 less for
  each further error.
- Domain score: weighted average of scored checks. DMARC counts three times; SPF, DKIM, MX and DNSSEC twice.
- Inventory and discovery checks (subdomains, DNS inventory, CT timeline, Microsoft 365, ...) are shown but not scored.
- Grade: A from 90, B from 80, C from 70, D from 60, otherwise F.

## Composition layouts

`HtmlCompositionReport.Generate(...)` renders the same assessment report for every profile. The earlier `Document`
and `Dashboard` layouts were retired; the enum values remain (obsolete) so existing callers keep compiling.

## Dependencies

- HtmlForgeX 1.1.0 or later
- DomainDetective
- DomainDetective.Reports
