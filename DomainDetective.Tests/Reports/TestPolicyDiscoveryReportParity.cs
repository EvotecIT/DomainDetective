using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestPolicyDiscoveryReportParity {
    [Fact]
    public async Task FailedMailPolicyDiscoveryRemainsUnknownInGeneratedReports() {
        var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) =>
            Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await check.VerifySPF("example.com");
        await check.VerifyDMARC("example.com");

        var spf = Converters.Convert(check.SpfAnalysis);
        var dmarc = Converters.Convert(check.DmarcAnalysis);
        Assert.Equal("Unknown", spf.RecordPresence);
        Assert.Equal("Unknown", dmarc.RecordPresence);
        Assert.Equal("Unknown", dmarc.DkimAlignment);
        Assert.Equal("Unknown", dmarc.SpfAlignment);
        Assert.Contains("unknown", spf.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(dmarc.Highlights, highlight => highlight.StartsWith("Published policy:", StringComparison.Ordinal));
        var assessment = DomainAssessmentBuilder.Build(new object[] { spf, dmarc });
        var domain = Assert.Single(assessment.Domains);
        foreach (var kind in new[] { HealthCheckType.SPF, HealthCheckType.DMARC }) {
            var policy = Assert.Single(domain.Checks, c => c.Check == kind);
            Assert.Contains(policy.Metrics, metric => metric.Label == "Record" && metric.Value == "Unknown");
            Assert.False(policy.EvidenceComplete);
            Assert.Null(policy.Score);
            Assert.Equal(CheckOutcome.Incomplete, policy.Outcome);
            Assert.Equal(0, policy.WarningCount);
            Assert.All(policy.Findings, finding => Assert.True(finding.IsEvidenceGap));
            Assert.All(policy.Metrics, metric => Assert.Equal(MetricState.Neutral, metric.State));
        }

        var directory = Path.Combine(Path.GetTempPath(), "DomainDetective-policy-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var items = new object[] { spf, dmarc };
            var htmlPath = Path.Combine(directory, "policies.html");
            var wordPath = Path.Combine(directory, "policies.docx");
            var excelPath = Path.Combine(directory, "policies.xlsx");
            HtmlCompositionReport.Generate(htmlPath, items, ReportScope.Detailed);
            DomainDetective.Reports.Office.AssessmentWordReport.Generate(wordPath, DomainAssessmentBuilder.Build(items), new DomainDetective.Reports.Office.AssessmentWordOptions { ShowInfoFindings = false });
            AssessmentExcelReport.Generate(excelPath, DomainDetective.Reports.DomainAssessmentBuilder.Build(items));
            var markdown = DomainDetective.Reports.Markdown.AssessmentMarkdownReport.Render(assessment);
            Assert.Contains("Incomplete", markdown);
            Assert.DoesNotContain("| Warning |", markdown);
            // The producer's diagnostic is retained, but its rendered message has a neutral tone.
            using (var archive = ZipFile.OpenRead(wordPath)) {
                XNamespace w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
                using var stream = archive.GetEntry("word/document.xml")!.Open();
                var xml = XDocument.Load(stream);
                foreach (var finding in domain.Checks.SelectMany(c => c.Findings)) {
                    var runs = xml.Descendants(w + "r").Where(r => r.Elements(w + "t").Any(t => t.Value == finding.Message)).ToList();
                    Assert.NotEmpty(runs);
                    // Action-table messages use the paper ink; the finding detail is explicitly neutral.
                    Assert.Contains(runs, r => (string?)r.Element(w + "rPr")?.Element(w + "color")?.Attribute(w + "val") == "687078");
                }
            }

            // The assessment report states the record as unknown, never missing, when the lookup failed.
            string htmlText = NormalizeText(File.ReadAllText(htmlPath));
            Assert.True(Regex.Matches(htmlText, @"Unknown\s+Record").Count >= 2, "The SPF and DMARC checks should each show an unknown record.");
            Assert.DoesNotContain("anyone can send as this domain", htmlText);
            Assert.DoesNotContain("spoofed mail is not rejected", htmlText);
            foreach (string path in new[] { wordPath, excelPath }) {
                string text = ReportArtifactText.Read(path);
                Assert.Contains("Unknown", text);
                Assert.DoesNotContain("anyone can send as this domain", text);
                Assert.DoesNotContain("spoofed mail is not rejected", text);
                Assert.Contains(SpfCodes.QueryFailed, text);
                Assert.Contains(DmarcCodes.QueryFailed, text);
            }
        } finally {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void IncompleteAcquisitionDoesNotHideObservedDefectsOrAncillaryLookupWarnings() {
        var initial = new SpfRecordInfo {
            Subject = "example.test", DnsQueryFailed = true, SpfRecordExists = false,
            Assessments = new[] {
                new Assessment { Code = SpfCodes.QueryFailed, Severity = AssessmentSeverity.Warning, Message = "Acquisition unavailable." },
                new Assessment { Code = "SPF.ObservedDefect", Severity = AssessmentSeverity.Error, Message = "Observed defect remains an error." }
            }
        };
        var incomplete = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { initial }).Domains).Checks);
        Assert.False(incomplete.EvidenceComplete);
        Assert.Equal(CheckOutcome.Error, incomplete.Outcome);
        Assert.Equal(1, incomplete.ErrorCount);
        Assert.Equal(0, incomplete.WarningCount);
        Assert.True(incomplete.Findings.Single(f => f.Code == SpfCodes.QueryFailed).IsEvidenceGap);
        Assert.False(incomplete.Findings.Single(f => f.Code == "SPF.ObservedDefect").IsEvidenceGap);
        Assert.Equal(AssessmentSeverity.Warning, initial.Assessments[0].Severity);

        initial.SpfRecordExists = true;
        initial.SpfRecord = "v=spf1 include:_spf.example.test -all";
        initial.Assessments = new[] { initial.Assessments[0] };
        var ancillary = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { initial }).Domains).Checks);
        Assert.True(ancillary.EvidenceComplete);
        Assert.Equal(CheckOutcome.Warning, ancillary.Outcome);
        Assert.Equal(1, ancillary.WarningCount);
        Assert.NotNull(ancillary.Score);
        Assert.False(Assert.Single(ancillary.Findings).IsEvidenceGap);
    }

    [Fact]
    public void DmarcReportCountsBothMailtoAndHttpDestinations() {
        var view = new DmarcRecordInfo {
            Subject = "example.com",
            Check = HealthCheckType.DMARC,
            DmarcRecordExists = true,
            MailtoRua = new[] { "mailto:agg@example.com" },
            HttpRua = new[] { "https://reports.example.com/agg" },
            HttpRuf = new[] { "https://reports.example.com/forensic" }
        };

        var check = Assert.Single(Assert.Single(DomainAssessmentBuilder.Build(new object[] { view }).Domains).Checks);
        Assert.Contains(check.Metrics, metric => metric.Label == "Aggregate reports" && metric.Value == "2 addresses");
        var destinations = Assert.Single(check.Evidence, evidence => evidence.Title == "Report destinations");
        Assert.Contains(destinations.Rows, row => row[0] == "Aggregate (rua)" && row[1] == "mailto:agg@example.com");
        Assert.Contains(destinations.Rows, row => row[0] == "Aggregate (rua)" && row[1] == "https://reports.example.com/agg");
        Assert.Contains(destinations.Rows, row => row[0] == "Failure (ruf)" && row[1] == "https://reports.example.com/forensic");
    }

    private static string NormalizeText(string source) =>
        Regex.Replace(Regex.Replace(source, "<[^>]+>", " "), @"\s+", " ");
}
