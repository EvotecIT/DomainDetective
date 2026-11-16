using System.IO.Compression;
using System.Net;
using DomainDetective.Profiles;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public partial class TestAssessmentExports {
    // Made-up evidence: listed by one feed, registered 12 days ago, VirusTotal never queried.
    private static DomainRiskProfile RiskProfile(string domain) {
        var now = new DateTimeOffset(2026, 10, 21, 17, 32, 0, TimeSpan.Zero);
        var evidence = new DomainRiskEvidence {
            Domain = domain,
            DomainBlocklistState = EvidenceState.Clean,
            HostBlocklistState = EvidenceState.Clean,
            RegistrationSource = "RDAP",
            CreatedState = EvidenceState.Observed, CreatedUtc = now.AddDays(-12),
            ExpiryState = EvidenceState.Observed, ExpiresUtc = now.AddYears(1),
            StatusState = EvidenceState.Observed, RegistrarState = EvidenceState.Observed, Registrar = "Example Registrar",
            CtState = EvidenceState.Observed, CtSource = "crt.sh", CtFirstSeenUtc = now.AddDays(-11), UniqueCertificates = 2,
            InventoryState = EvidenceState.Observed, NameServerState = EvidenceState.Observed,
            DnssecState = EvidenceState.Observed, Dnssec = DnssecValidationStatus.Insecure, PtrState = EvidenceState.Observed,
            NetworkState = EvidenceState.NotQueried
        };
        evidence.Issuers["Example CA"] = 2;
        evidence.Feeds.Add(new ThreatFeedEvidence { Id = "gsb", Name = "Google Safe Browsing", Weight = 0.25, State = EvidenceState.Observed, Listed = true });
        evidence.Feeds.Add(new ThreatFeedEvidence { Id = "virustotal", Name = "VirusTotal", Weight = 0.20, State = EvidenceState.NotQueried, Action = "Add a VirusTotal API key" });
        return DomainRiskProfileEvaluator.Evaluate(evidence, now);
    }

    [Fact]
    public void EveryFormatPrintsTheSameRiskVerdictSignalsAndGaps() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create(2);
            foreach (DomainAssessment domain in report.Domains) domain.RiskProfile = RiskProfile(domain.Domain);
            DomainRiskProfile profile = report.Domains[0].RiskProfile!;
            string html = WebUtility.HtmlDecode(AssessmentHtmlReport.Render(report));
            string markdown = AssessmentMarkdownReport.Render(report);
            string wordPath = Path.Combine(directory, "assessment.docx"), excelPath = Path.Combine(directory, "assessment.xlsx");
            AssessmentWordReport.Generate(wordPath, report);
            AssessmentExcelReport.Generate(excelPath, report);
            using var word = ZipFile.OpenRead(wordPath);
            using var excel = ZipFile.OpenRead(excelPath);
            string[] outputs = { html, WordText(Load(word, "word/document.xml")), WorkbookText(excel), markdown };

            foreach (string output in outputs) {
                Assert.Contains(Wording.RiskVerdict(profile), output);
                foreach (RiskSignal signal in Wording.ShownSignals(profile)) Assert.Contains(signal.Reason, output);
            }
            // The page, paper and Markdown formats also rank the domains and print what would raise confidence.
            foreach (string output in new[] { outputs[0], outputs[1], outputs[3] }) {
                Assert.Contains("Risk by domain", output);
                Assert.Contains("Add a VirusTotal API key", output);
            }
            Assert.Contains("data-dd-risk-profile=\"" + report.Domains[0].Domain + "\"", AssessmentHtmlReport.Render(report));
        });
    }

    [Fact]
    public void ExcelGetsOneRowPerSignalAndPerEvidenceItem() {
        InDirectory(directory => {
            var report = AssessmentExportFixture.Create();
            report.Domains[0].RiskProfile = RiskProfile(report.Domains[0].Domain);
            string path = Path.Combine(directory, "assessment.xlsx");
            AssessmentExcelReport.Generate(path, report);
            using var excel = ZipFile.OpenRead(path);
            string workbook = Load(excel, "xl/workbook.xml").ToString();

            // One risk sheet holds the verdict, one row per signal and one row per evidence item.
            Assert.Contains("Risk profile", workbook);
            Assert.DoesNotContain("Risk signals", workbook);
            string text = WorkbookText(excel);
            DomainRiskProfile profile = report.Domains[0].RiskProfile!;
            foreach (RiskSignal signal in profile.Signals) Assert.Contains(signal.Reason, text);
            foreach (EvidenceItem item in profile.Facets.SelectMany(f => f.Evidence)) Assert.Contains(item.Label, text);
            // Internal rule identifiers stay out of the workbook.
            Assert.DoesNotContain("reputation.listed.gsb", text);
        });
    }

    [Fact]
    public void ReportsWithoutAProfileAreUnchanged() {
        var report = AssessmentExportFixture.Create();
        Assert.DoesNotContain("Risk profile", AssessmentMarkdownReport.Render(report));
        Assert.DoesNotContain("data-dd-risk-profile", AssessmentHtmlReport.Render(report));
    }

    [Fact]
    public void TheBuilderAttachesTheProfileViewToItsDomainWithoutAddingACheck() {
        var view = new DomainRiskProfileInfo { Subject = "Example.TEST.", Profile = RiskProfile("example.test") };

        DomainAssessmentReport report = DomainAssessmentBuilder.Build(new object[] { view });

        DomainAssessment domain = Assert.Single(report.Domains);
        Assert.Equal("example.test", domain.Domain);
        Assert.Same(view.Profile, domain.RiskProfile);
        Assert.Empty(domain.Checks);
        Assert.Empty(report.UnassignedInputs);
    }

    [Fact]
    public void TheProfileSurvivesTheAssessmentJson() {
        var report = AssessmentExportFixture.Create();
        report.Domains[0].RiskProfile = RiskProfile(report.Domains[0].Domain);

        DomainAssessmentReport? copy = DomainAssessmentJson.Deserialize(DomainAssessmentJson.Serialize(report));

        DomainRiskProfile? profile = copy?.Domains[0].RiskProfile;
        Assert.NotNull(profile);
        Assert.Equal(report.Domains[0].RiskProfile!.RiskScore, profile!.RiskScore);
        Assert.Equal(report.Domains[0].RiskProfile!.RiskLevel, profile.RiskLevel);
        Assert.Equal(report.Domains[0].RiskProfile!.Signals.Count, profile.Signals.Count);
    }
}
