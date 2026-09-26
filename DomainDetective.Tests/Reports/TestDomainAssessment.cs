using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports {
    public class TestDomainAssessment {
        private static Assessment Warning(string code, string message) => new() { Severity = AssessmentSeverity.Warning, Code = code, Message = message };
        private static Assessment Error(string code, string message) => new() { Severity = AssessmentSeverity.Error, Code = code, Message = message };
        private static Assessment Info(string code, string message) => new() { Severity = AssessmentSeverity.Info, Code = code, Message = message };

        private static List<object> SampleViews() => new() {
            new SpfRecordInfo {
                Check = HealthCheckType.SPF, Area = AnalysisArea.Mail, Subject = "Example.org.",
                SpfRecord = "v=spf1 include:_spf.example.net -all", SpfRecordExists = true, DnsLookupsCount = 2, AllMechanism = "-all",
                Assessments = new[] { Warning("SPF.Lookups.High", "Two lookups used."), Info("SPF.Record.Present", "Record present.") }
            },
            new DmarcRecordInfo {
                Check = HealthCheckType.DMARC, Area = AnalysisArea.Mail, Subject = "example.org",
                Assessments = new[] { Error("DMARC.Record.Missing", "No DMARC record published.") }
            },
            // Two selectors of one check are merged into one check with a results table.
            new DkimRecordInfo { Check = HealthCheckType.DKIM, Area = AnalysisArea.Mail, Subject = "example.org", Selector = "s1", KeyLength = 2048, DkimRecordExists = true, ValidPublicKey = true, StartsCorrectly = true, ValidKeyLength = true },
            new DkimRecordInfo { Check = HealthCheckType.DKIM, Area = AnalysisArea.Mail, Subject = "example.org", Selector = "s2", KeyLength = 1024, DkimRecordExists = true, ValidPublicKey = true, StartsCorrectly = true, WeakKey = true },
            new MxInfo { Check = HealthCheckType.MX, Area = AnalysisArea.Mail, Subject = "b.example" },
            // An inventory check is shown but not scored.
            new WildcardDnsInfo { Check = HealthCheckType.WILDCARDDNS, Area = AnalysisArea.DNS, Subject = "https://example.org/", CatchAll = false },
            new SubdomainsInfo { Check = HealthCheckType.SUBDOMAINS, Area = AnalysisArea.DNS, Subject = "example.org", Assessments = new[] { Warning("SUB.Dangling", "Dangling name.") } },
            "not a view"
        };

        [Fact]
        public void Build_GroupsViewsByDomainAndScoresChecks() {
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(SampleViews(), new DomainAssessmentOptions { Title = "Test" });

            Assert.Equal(new[] { "b.example", "example.org" }, report.Domains.Select(static d => d.Domain));
            Assert.Equal(new[] { "String" }, report.UnassignedInputs);

            DomainAssessment domain = report.Domains.Single(static d => d.Domain == "example.org");
            CheckAssessment spf = domain.Checks.Single(static c => c.Key == "spf");
            Assert.Equal(CheckOutcome.Warning, spf.Outcome);
            Assert.Equal(85, spf.Score);
            Assert.Equal("Sender Policy Framework", spf.LongTitle);
            Assert.Contains(spf.Evidence, static e => e.Kind == CheckEvidenceKind.Code && e.Text!.StartsWith("v=spf1", StringComparison.Ordinal));
            Assert.Contains(spf.Metrics, static m => m.Label == "DNS lookups" && m.Value == "2 / 10" && m.State == MetricState.Good);
            Assert.Contains(spf.Metrics, static m => m.Label == "Ends with" && m.Value == "-all (fail)" && m.State == MetricState.Good);

            CheckAssessment dmarc = domain.Checks.Single(static c => c.Key == "dmarc");
            Assert.Equal(CheckOutcome.Error, dmarc.Outcome);
            Assert.Equal(40, dmarc.Score);
            Assert.Equal(3, dmarc.Weight);

            CheckAssessment dkim = domain.Checks.Single(static c => c.Key == "dkim");
            Assert.Equal(2, dkim.Sources.Count);
            CheckEvidence results = dkim.Evidence.First();
            Assert.Equal(CheckEvidenceKind.Table, results.Kind);
            Assert.Equal("Selectors", results.Title);
            Assert.Equal(2, results.Rows.Count);
            Assert.Contains(dkim.Metrics, static m => m.Label == "Weak keys" && m.Value == "1" && m.State == MetricState.Warning);

            CheckAssessment wildcard = domain.Checks.Single(static c => c.Key == "wildcarddns");
            Assert.Equal(CheckOutcome.Pass, wildcard.Outcome);

            CheckAssessment subdomains = domain.Checks.Single(static c => c.Key == "subdomains");
            Assert.False(subdomains.Scored);
            Assert.Equal(CheckOutcome.Warning, subdomains.Outcome);

            // Weighted: SPF 85×2, DMARC 40×3, DKIM 100×2, wildcard 100×1 → 590 / 8.
            Assert.Equal(74, domain.Score);
            Assert.Equal("C", domain.Grade);
            Assert.Equal(1, domain.ErrorChecks);
            Assert.Contains(domain.Areas, static a => a.Area == AnalysisArea.Mail && a.Attention == 2);
            Assert.Equal(AnalysisArea.Mail, domain.Checks[0].Area);
        }

        [Fact]
        public void Build_DmarcModuleShowsPolicyAndWhereReportsGo() {
            var views = new List<object> {
                new DmarcRecordInfo {
                    Check = HealthCheckType.DMARC, Area = AnalysisArea.Mail, Subject = "example.org",
                    DmarcRecordExists = true, DmarcRecord = "v=DMARC1; p=none; rua=mailto:d@example.org,mailto:r@vendor.example",
                    Policy = "none", Pct = 50,
                    MailtoRua = new[] { "mailto:d@example.org", "mailto:r@vendor.example" },
                    UnauthorizedExternalReportDomains = new[] { "vendor.example" }
                }
            };

            CheckAssessment dmarc = DomainAssessmentBuilder.Build(views).Domains.Single().Checks.Single();

            Assert.Equal(new[] { "Policy", "Subdomains", "Applied to", "Aggregate reports", "Alignment" }, dmarc.Metrics.Select(static m => m.Label));
            Assert.Equal(MetricState.Warning, dmarc.Metrics[0].State);
            Assert.Equal("50%", dmarc.Metrics[2].Value);
            Assert.Equal("none (inherited)", dmarc.Metrics[1].Value);
            CheckEvidence destinations = Assert.Single(dmarc.Evidence, static e => e.Title == "Report destinations");
            Assert.Equal(new[] { "Not needed", "Missing" }, destinations.Rows.Select(static r => r[2]));
            // The curated reading replaces the generic property listing.
            Assert.DoesNotContain(dmarc.Facts, static f => f.Label == "Mailto rua");
        }

        [Fact]
        public void Build_ModulesReportMissingRecordsAsTheHeadline() {
            var views = new List<object> {
                new SpfRecordInfo { Check = HealthCheckType.SPF, Area = AnalysisArea.Mail, Subject = "example.org" },
                new MtastsInfo { Check = HealthCheckType.MTASTS, Area = AnalysisArea.Mail, Subject = "example.org" }
            };

            DomainAssessment domain = DomainAssessmentBuilder.Build(views).Domains.Single();

            CheckMetric spf = Assert.Single(domain.Checks.Single(static c => c.Key == "spf").Metrics);
            Assert.Equal(("Record", "Missing", MetricState.Error), (spf.Label, spf.Value, spf.State));
            CheckMetric sts = Assert.Single(domain.Checks.Single(static c => c.Key == "mtasts").Metrics);
            Assert.Equal("Not published", sts.Value);
        }

        [Fact]
        public void Build_NamesReportHistoryViews() {
            var views = new List<object> { new DmarcAggregateTimeSeriesInfo { Subject = "example.org" } };

            CheckAssessment reports = DomainAssessmentBuilder.Build(views).Domains.Single().Checks.Single();

            Assert.Equal("dmarc-reports", reports.Key);
            Assert.Equal("DMARC aggregate reports", reports.Title);
            Assert.Equal(AnalysisArea.Mail, reports.Area);
            Assert.False(reports.Scored);
        }

        [Fact]
        public void Html_ShowsKeyNumbersAndControls() {
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(SampleViews().Where(static v => v is not MxInfo { Subject: "b.example" }).ToList());

            string html = AssessmentHtmlReport.Render(report);

            Assert.Contains("Controls", html);
            Assert.Contains("DNS lookups · limit set by RFC 7208", html);
            Assert.Contains("-all (fail)", html);
        }

        [Fact]
        public void Html_DomainProfileDrawsTheMailChainAndAVerdict() {
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(SampleViews().Where(static v => v is not MxInfo { Subject: "b.example" }).ToList());

            string html = AssessmentHtmlReport.Render(report);

            Assert.Contains("Can anyone send as example.org?", html);
            Assert.Contains("hfx-as-flow", html);
            Assert.Contains("DKIM · signed by", html);
            Assert.Contains("DMARC · policy", html);
            // The missing DMARC record is the headline of its step and the first thing to fix.
            Assert.Contains("hfx-as-flow-step is-emphasis", html);
            Assert.Contains("Fix first: DMARC", html);
            // The weak selector is called out as its own line.
            Assert.Contains("s2 · RSA 1,024", html);
        }

        [Fact]
        public void Build_InfersCheckAndAreaForHandBuiltViews() {
            // As built in PowerShell: only the subject and status are set, so Check is left at its default (DMARC).
            var views = new List<object> {
                new SpfRecordInfo { Subject = "example.org", Status = "OK" },
                new DmarcRecordInfo { Subject = "example.org", Status = "Warning" },
                new MxInfo { Subject = "example.org", Status = "OK" },
                new BimiRecordInfo { Subject = "example.org" }
            };

            DomainAssessment domain = DomainAssessmentBuilder.Build(views).Domains.Single();

            Assert.Equal(new[] { "dmarc", "mx", "spf", "bimi" }.OrderBy(static k => k), domain.Checks.Select(static c => c.Key).OrderBy(static k => k));
            Assert.All(domain.Checks, static c => Assert.Equal(AnalysisArea.Mail, c.Area));
            Assert.Equal(HealthCheckType.SPF, domain.Checks.Single(static c => c.Key == "spf").Check);
        }

        [Fact]
        public void Build_SerializesToJsonWithoutSourceViews() {
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(SampleViews());
            string json = JsonSerializer.Serialize(report);

            Assert.Contains("\"Domain\":\"example.org\"", json, StringComparison.Ordinal);
            Assert.DoesNotContain("\"Sources\"", json, StringComparison.Ordinal);
            DomainAssessmentReport? roundTrip = JsonSerializer.Deserialize<DomainAssessmentReport>(json);
            Assert.Equal(report.Domains.Count, roundTrip!.Domains.Count);
        }

        [Fact]
        public void Html_RendersAssessmentShellOffline() {
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(SampleViews(), new DomainAssessmentOptions { Title = "Test" });
            string html = AssessmentHtmlReport.Render(report);

            Assert.Contains("id=\"hfx-asr-panel-summary\"", html, StringComparison.Ordinal);
            Assert.Contains("id=\"hfx-asr-panel-domain-example-org\"", html, StringComparison.Ordinal);
            Assert.Contains("id=\"domain-example-org-dmarc\"", html, StringComparison.Ordinal);
            Assert.Contains("data-dd-domain=\"example.org\"", html, StringComparison.Ordinal);
            Assert.Contains("No DMARC record published.", html, StringComparison.Ordinal);
            Assert.Contains("v=spf1 include:_spf.example.net -all", html, StringComparison.Ordinal);
            Assert.Contains("Coverage", html, StringComparison.Ordinal);
            Assert.DoesNotContain("cdn.jsdelivr.net", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<script src=\"http", html, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void HtmlCompositionReport_AssessmentProfileWritesAssessmentReport() {
            string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
            try {
                HtmlCompositionReport.Generate(path, SampleViews(), ReportScope.Normal, titleOverride: "Profile test", profile: HtmlProfile.Assessment);
                string html = System.IO.File.ReadAllText(path);
                Assert.Contains("hfx-asr-panel-summary", html, StringComparison.Ordinal);
                Assert.Contains("Profile test", html, StringComparison.Ordinal);
            } finally {
                if (System.IO.File.Exists(path)) System.IO.File.Delete(path);
            }
        }

        [Fact]
        public async System.Threading.Tasks.Task CompositionExport_WritesAssessmentJson() {
            string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            try {
                CompositionExportResult result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
                    Items = SampleViews(),
                    Formats = new[] { ReportFormat.Json, ReportFormat.Html },
                    ExportPath = System.IO.Path.Combine(directory, "report"),
                    AutoCollectTtl = false,
                    Title = "Export test"
                });

                ReportResult json = result.Reports.Single(static r => r.Format == ReportFormat.Json);
                Assert.True(json.Success, json.ErrorMessage);
                DomainAssessmentReport? report = DomainAssessmentJson.Deserialize(System.IO.File.ReadAllText(json.FilePath));
                Assert.Equal("Export test", report!.Title);
                Assert.Contains(report.Domains, static d => d.Domain == "example.org" && d.Checks.Any(static c => c.Key == "dmarc" && c.Outcome == CheckOutcome.Error));
                Assert.Contains("\"outcome\": \"Error\"", System.IO.File.ReadAllText(json.FilePath), StringComparison.Ordinal);

                ReportResult html = result.Reports.Single(static r => r.Format == ReportFormat.Html);
                Assert.True(html.Success, html.ErrorMessage);
                Assert.Contains("hfx-asr-panel-summary", System.IO.File.ReadAllText(html.FilePath), StringComparison.Ordinal);
            } finally {
                if (System.IO.Directory.Exists(directory)) System.IO.Directory.Delete(directory, recursive: true);
            }
        }

        [Fact]
        public void Html_RendersPunycodeDomainsAndUniqueIds() {
            var views = new List<object> {
                new SpfRecordInfo { Check = HealthCheckType.SPF, Subject = "xn--bcher-kva.de" },
                new MxInfo { Check = HealthCheckType.MX, Subject = "example.com" },
                new SpfRecordInfo { Check = HealthCheckType.SPF, Subject = "example.com.mx" }
            };
            string html = AssessmentHtmlReport.Render(DomainAssessmentBuilder.Build(views));

            Assert.Contains("data-dd-domain=\"xn--bcher-kva.de\"", html, StringComparison.Ordinal);
            // example.com + MX and the domain example.com.mx would both be "domain-example-com-mx" without de-duplication.
            Assert.Contains("id=\"hfx-asr-panel-domain-example-com-mx\"", html, StringComparison.Ordinal);
            Assert.Contains("id=\"domain-example-com-mx-2\"", html, StringComparison.Ordinal);
        }

        [Fact]
        public void Build_DoesNotScoreViewsThatNameNoCheck() {
            var views = new List<object> {
                new DomainOverallInfo { Subject = "example.org", ErrorCount = 5, WarningCount = 3 },
                new SpfRecordInfo { Check = HealthCheckType.SPF, Subject = "example.org" }
            };
            DomainAssessment domain = DomainAssessmentBuilder.Build(views).Domains.Single();

            CheckAssessment overall = domain.Checks.Single(static c => c.Check == null);
            Assert.False(overall.Scored);
            Assert.Equal(CheckOutcome.Error, overall.Outcome);
            Assert.Equal(5, overall.ErrorCount);
            Assert.Equal(100, domain.Score);
        }

        [Fact]
        public void Build_KeepsUnnamedHandBuiltViewsOutOfDmarcAndSkipsNonDomainSubjects() {
            var views = new List<object> {
                new DmarcRecordInfo { Subject = "example.org" },
                new MailTlsInfo { Subject = "example.org" },
                new ArcInfo { Subject = "Message Headers" }
            };
            DomainAssessmentReport report = DomainAssessmentBuilder.Build(views);

            DomainAssessment domain = report.Domains.Single();
            Assert.Equal(2, domain.Checks.Count);
            Assert.Single(domain.Checks, static c => c.Key == "dmarc");
            Assert.Contains("ArcInfo", report.UnassignedInputs);
        }

        [Fact]
        public void Html_EncodesUntrustedValues() {
            var views = new List<object> {
                new SpfRecordInfo {
                    Check = HealthCheckType.SPF, Area = AnalysisArea.Mail, Subject = "example.org",
                    SpfRecord = "v=spf1 <script>alert(1)</script> -all",
                    Assessments = new[] { Warning("X", "<img src=x onerror=alert(1)>") }
                }
            };
            string html = AssessmentHtmlReport.Render(DomainAssessmentBuilder.Build(views));

            Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
            Assert.DoesNotContain("<img src=x onerror", html, StringComparison.Ordinal);
        }
    }
}
