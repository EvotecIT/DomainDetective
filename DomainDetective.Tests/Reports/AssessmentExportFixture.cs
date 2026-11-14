using DomainDetective.Reports;

namespace DomainDetective.Tests.Reports;

/// <summary>Entirely made-up report data; no acquisition, DNS calls or certificate stores.</summary>
internal static class AssessmentExportFixture {
    internal static DomainAssessmentReport Create(int count = 1) {
        var report = new DomainAssessmentReport {
            GeneratedAtUtc = new DateTimeOffset(2026, 10, 21, 17, 32, 0, TimeSpan.Zero),
            Score = 88, Grade = "B"
        };
        for (int i = 1; i <= count; i++) {
            string name = count == 1 ? "example.test" : $"example{i:00}.example.test";
            var domain = new DomainAssessment { Domain = name, Score = 88, Grade = "B" };
            domain.Checks.Add(Check("dmarc", "DMARC", HealthCheckType.DMARC, AnalysisArea.Mail, CheckOutcome.Error,
                "The published policy permits spoofed mail.", "Policy", "none"));
            domain.Checks.Add(Check("spf", "SPF", HealthCheckType.SPF, AnalysisArea.Mail, CheckOutcome.Pass, null, "Ends with", "-all (fail)"));
            domain.Checks.Add(Check("dkim", "DKIM", HealthCheckType.DKIM, AnalysisArea.Mail, CheckOutcome.Pass, null, "Selectors found", "2"));
            domain.Checks.Add(Check("mx", "MX", HealthCheckType.MX, AnalysisArea.Mail, CheckOutcome.Pass, null, "Mail servers", "2"));
            domain.Checks.Add(Check("mtasts", "MTA-STS", HealthCheckType.MTASTS, AnalysisArea.Mail, CheckOutcome.Pass, null, "Mode", "enforce"));
            domain.Checks.Add(Check("tlsrpt", "TLS-RPT", HealthCheckType.TLSRPT, AnalysisArea.Mail, CheckOutcome.Pass, null, "Report addresses", "1"));
            domain.Checks.Add(Check("bimi", "BIMI", HealthCheckType.BIMI, AnalysisArea.Mail, CheckOutcome.Pass, null, "Logo", "Published"));
            domain.Checks.Add(Check("dnssec", "DNSSEC", HealthCheckType.DNSSEC, AnalysisArea.DNS, CheckOutcome.Pass, null, "Validation", "Secure"));
            domain.Checks.Add(Check("caa", "CAA", HealthCheckType.CAA, AnalysisArea.DNS, CheckOutcome.Pass, null, "Issuers", "1"));
            domain.Checks.Add(Check("ns", "NS", HealthCheckType.NS, AnalysisArea.DNS, CheckOutcome.Pass, null, "Name servers", "2"));
            domain.Checks.Add(Check("cert", "Certificate", HealthCheckType.CERT, AnalysisArea.Web, CheckOutcome.Warning,
                "The certificate expires in 12 days.", "Days remaining", "12"));
            domain.Checks.Add(Check("rdap", "Registration", HealthCheckType.RDAP, AnalysisArea.General, CheckOutcome.Info, null, "Status", "Registered"));
            domain.Checks.Add(Check("dnsbl", "DNSBL", HealthCheckType.DNSBL, AnalysisArea.Security, CheckOutcome.Pass, null, "Listings", "0"));

            foreach (CheckAssessment check in domain.Checks) {
                check.Facts.Add(new CheckFact { Label = "Subject", Value = name });
                if (check.Key == "dnssec") check.Facts.Add(new CheckFact { Label = "Validation status", Value = "Secure" });
                if (check.Key is "mx" or "ns" or "dkim") {
                    check.Evidence.Add(new CheckEvidence {
                        Title = check.Key == "dkim" ? "Selectors" : "Hosts", Kind = CheckEvidenceKind.Table,
                        Columns = { "Name", "Result" },
                        Rows = { new List<string> { "primary-identifier." + name, "Pass" }, new List<string> { "secondary-identifier." + name, "Pass" } }
                    });
                }
                if (check.Key is "spf" or "dmarc" or "mtasts") check.Evidence.Add(new CheckEvidence {
                    Title = "Published record", Kind = CheckEvidenceKind.Code,
                    Text = check.Key == "spf" ? "v=spf1 include:_spf." + name + " -all" : check.Key == "dmarc" ? "v=DMARC1; p=none; rua=mailto:reports@" + name : "version: STSv1\nmode: enforce\nmx: mail." + name + "\nmax_age: 86400"
                });
            }
            foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
                var checks = domain.Checks.Where(c => c.Area == area).ToList();
                if (checks.Count > 0) domain.Areas.Add(new AreaScore { Area = area, Score = Average(checks), Checks = checks.Count, Attention = checks.Count(AssessmentReportWording.NeedsAttention) });
            }
            domain.Score = Average(domain.Checks);
            domain.Grade = domain.Score >= 90 ? "A" : domain.Score >= 80 ? "B" : "C";
            domain.ErrorChecks = 1; domain.WarningChecks = 1; domain.PassedChecks = 10;
            report.Domains.Add(domain);
        }
        report.Score = (int)Math.Round(report.Domains.Average(d => d.Score!.Value));
        report.Grade = report.Score >= 90 ? "A" : report.Score >= 80 ? "B" : "C";
        return report;
    }

    private static int? Average(List<CheckAssessment> checks) {
        var scored = checks.Where(c => c.Scored).ToList();
        return scored.Count == 0 ? null : (int)Math.Round(scored.Sum(c => c.Score!.Value * c.Weight) / (double)scored.Sum(c => c.Weight));
    }

    private static CheckAssessment Check(string key, string title, HealthCheckType type, AnalysisArea area,
        CheckOutcome outcome, string? finding, string metric, string value) {
        var check = new CheckAssessment {
            Key = key, Title = title, Check = type, Area = area, Outcome = outcome,
            Scored = outcome != CheckOutcome.Info, Score = outcome == CheckOutcome.Error ? 40 : outcome == CheckOutcome.Warning ? 85 : 100,
            Weight = type == HealthCheckType.DMARC ? 3 : type is HealthCheckType.SPF or HealthCheckType.DKIM or HealthCheckType.MX or HealthCheckType.DNSSEC ? 2 : 1,
            ErrorCount = outcome == CheckOutcome.Error ? 1 : 0, WarningCount = outcome == CheckOutcome.Warning ? 1 : 0,
            Summary = title + " fixture result.", Description = "Made-up evidence for export review.",
            Metrics = { new CheckMetric { Label = metric, Value = value } }
        };
        if (finding != null) {
            check.Findings.Add(new CheckFinding { Severity = outcome == CheckOutcome.Error ? AssessmentSeverity.Error : AssessmentSeverity.Warning, Message = finding, Code = title + ".Fixture" });
            check.Recommendations.Add(new CheckGuidance {
                Title = title == "DMARC" ? "Enforce the mail policy" : "Renew the certificate",
                How = title == "DMARC" ? "Confirm all legitimate senders authenticate, then move the published policy to quarantine and reject." : "Issue and install a replacement certificate before the existing certificate expires.",
                Verify = "Repeat the check and confirm the expected result."
            });
        }
        return check;
    }
}
