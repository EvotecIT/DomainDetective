using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using HtmlForgeX;
using DomainDetective.Narratives;
using System.Net;
using System.Text.Json;

var directory = Path.GetFullPath(args[0]);
Directory.CreateDirectory(directory);
var report = new DomainAssessmentReport { Title = "Domain health", Grade = "B", Score = 84, GeneratedAtUtc = new DateTimeOffset(2026, 11, 2, 12, 0, 0, TimeSpan.Zero) };
var domain = new DomainAssessment { Domain = "example.org", Score = 84, Grade = "B", ErrorChecks = 1, WarningChecks = 1, PassedChecks = 4 };
report.Domains.Add(domain);
foreach (var (key, name, outcome, summary) in new[] {
    ("dmarc", "DMARC policy", CheckOutcome.Warning, "Messages are monitored, but spoofed mail is not rejected."),
    ("dnssec", "DNSSEC chain", CheckOutcome.Error, "The delegation points to a key that is no longer published."),
    ("spf", "SPF policy", CheckOutcome.Pass, "The policy authorizes the expected sending service."),
    ("tls", "HTTPS certificate", CheckOutcome.Pass, "The certificate is trusted and valid for the domain."),
    ("mx", "Mail routing", CheckOutcome.Pass, "Both mail exchangers respond."),
    ("caa", "Certificate authorities", CheckOutcome.Pass, "Issuance is limited to the expected authority.") }) {
    var check = new CheckAssessment { Key = key, Title = name, Outcome = outcome, Summary = summary };
    domain.Checks.Add(check);
    check.Facts.Add(new CheckFact { Label = "Domain", Value = domain.Domain });
    check.Evidence.Add(new CheckEvidence { Title = "Collected evidence", Text = key == "dmarc" ? "v=DMARC1; p=none; rua=mailto:dmarc@example.org" : summary });
    if (outcome != CheckOutcome.Pass) check.Recommendations.Add(new CheckGuidance { Title = "Review " + name, Why = summary, How = "Compare the published configuration with the intended policy.", Verify = "Run the check again after the authoritative records have converged." });
}
var dmarc = domain.Checks[0];
dmarc.LongTitle = "Domain-based Message Authentication, Reporting and Conformance";
dmarc.Description = "Compare the DMARC policy with the intended mail protection.";
dmarc.Scored = true; dmarc.Score = 70;
dmarc.Metrics.Add(new CheckMetric { Label = "Policy", Value = "Monitor", Note = "Rejection is not enabled", State = MetricState.Warning });
dmarc.Findings.Add(new CheckFinding { Code = "DMARC_MONITOR_ONLY", Target = "_dmarc.example.org", Message = "The published policy requests monitoring only.", Severity = DomainDetective.AssessmentSeverity.Warning });
dmarc.Positives.Add("Aggregate reporting is configured.");
dmarc.Highlights.Add("One DMARC policy record was collected.");
dmarc.Remediation = "Move from monitoring to enforcement after reviewing legitimate senders.";
dmarc.References.Add("https://www.rfc-editor.org/rfc/rfc7489");
dmarc.Recommendations[0].Impact = "Reduce the chance of successful domain spoofing.";
dmarc.Recommendations[0].Effort = "Review the current sending inventory.";
dmarc.Narrative = new NarrativeSections {
    Introduction = "DMARC connects SPF and DKIM results to a published domain policy.",
    WhyItMatters = "Receivers need an explicit policy for mail that fails alignment.",
    Details = { "Authorised forwarders may need separate verification." },
    Positives = { "Keep aggregate reports available during policy changes." },
    Remediations = { "Stage enforcement after validating legitimate sources." }
};
dmarc.Evidence.Add(new CheckEvidence { Title = "Policy answer", Kind = CheckEvidenceKind.Table,
    Columns = { "Record", "TTL", "Policy" }, Rows = { new() { "_dmarc.example.org", "300", "p=none" } } });
using var classic = AssessmentHtmlReport.Build(report);
var classicHtml = classic.ToString();
File.WriteAllText(Path.Combine(directory, "domain-classic.html"), classicHtml);
foreach (var mode in new[] { ThemeMode.Light, ThemeMode.Dark }) {
    var page = AssessmentHtmlReport.BuildPage(report, mode);
    page.Subtitle("DomainDetective · Illustrative assessment · 2 November 2026");
    page.Save(Path.Combine(directory, "domain-" + mode.ToString().ToLowerInvariant() + ".html"));
    if (mode == ThemeMode.Light) File.WriteAllText(Path.Combine(directory, "domain-print.html"), page.ToPrintHtml());
}
var printHtml = File.ReadAllText(Path.Combine(directory, "domain-print.html"));
var parity = new[] {
    ("Expanded check name", dmarc.LongTitle!), ("Description", dmarc.Description!),
    ("Metric label", "Policy"), ("Metric note", "Rejection is not enabled"),
    ("Finding code", "DMARC_MONITOR_ONLY"), ("Finding target", "_dmarc.example.org"),
    ("Finding", "The published policy requests monitoring only."), ("Positive", "Aggregate reporting is configured."),
    ("Highlight", "One DMARC policy record was collected."), ("Remediation", dmarc.Remediation!),
    ("Guidance impact", dmarc.Recommendations[0].Impact!), ("Guidance effort", dmarc.Recommendations[0].Effort!),
    ("Narrative introduction", dmarc.Narrative.Introduction), ("Narrative detail", dmarc.Narrative.Details[0]),
    ("Narrative remediation", dmarc.Narrative.Remediations[0]), ("Reference destination", dmarc.References[0]),
    ("Evidence cell", "p=none")
}.Select(item => new { field = item.Item1, classic = classicHtml.Contains(WebUtility.HtmlEncode(item.Item2)),
    pagePrint = printHtml.Contains(WebUtility.HtmlEncode(item.Item2)) }).ToArray();
File.WriteAllText(Path.Combine(directory, "domain-parity.json"), JsonSerializer.Serialize(parity, new JsonSerializerOptions { WriteIndented = true }));
if (parity.Any(item => !item.pagePrint)) throw new InvalidOperationException("The page projection lost assessment content; see domain-parity.json.");
Console.WriteLine(directory);
