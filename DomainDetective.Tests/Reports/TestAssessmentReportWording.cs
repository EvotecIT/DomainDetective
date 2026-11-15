using System.Net;
using AngleSharp.Html.Parser;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentReportWording {
    [Fact]
    public void InformationalAreaHasNeutralProgressAndScoredAreasUsePostureTones() {
        var document = new HtmlParser().ParseDocument(AssessmentHtmlReport.Render(AssessmentExportFixture.Create()));
        var scopes = document.QuerySelectorAll(".hfx-as-scope");
        var other = scopes.Single(scope => scope.QuerySelector(".hfx-as-scope-title")?.TextContent == "Other");
        Assert.Equal("info", other.GetAttribute("data-sev"));
        Assert.Contains("is-empty", other.QuerySelector(".hfx-as-progress")!.ClassList);
        Assert.Null(other.QuerySelector(".hfx-as-progress .is-pass"));
        var web = scopes.Single(scope => scope.QuerySelector(".hfx-as-scope-title")?.TextContent == "Web");
        Assert.Equal("elevated", web.QuerySelectorAll("[data-tone]").Single(value => value.TextContent == "85").GetAttribute("data-tone"));
    }

    [Theory]
    [InlineData(1, "The 1 check passes.")]
    [InlineData(2, "All 2 checks pass.")]
    public void PassingAreaUsesCountAgreement(int count, string expected) {
        var report = CreateArea(count, CheckOutcome.Pass);
        Assert.Equal(expected, Wording.AreaLine(report, report.Domains[0].Checks));
        Assert.Equal(count == 1 ? "1 check in 1 area: 1 passed." : "2 checks in 1 area: 2 passed.", Wording.ReportVerdictDetail(report));
    }

    [Theory]
    [InlineData(1, "Informational check only.")]
    [InlineData(2, "Informational checks only.")]
    public void InformationalAreaUsesCountAgreement(int count, string expected) {
        var report = CreateArea(count, CheckOutcome.Info);
        Assert.Equal(expected, Wording.AreaLine(report, report.Domains[0].Checks));
        Assert.Equal(count == 1 ? "1 check in 1 area: 0 passed, 1 informational." : "2 checks in 1 area: 0 passed, 2 informational.", Wording.ReportVerdictDetail(report));
    }

    [Theory]
    [InlineData(CheckOutcome.Pass, "The 1 check passes.")]
    [InlineData(CheckOutcome.Info, "Informational check only.")]
    public void HtmlArtifactUsesSingletonAreaWording(CheckOutcome outcome, string expected) {
        var report = CreateArea(1, outcome);
        string html = WebUtility.HtmlDecode(AssessmentHtmlReport.Render(report));
        Assert.Contains(expected, html);
        Assert.DoesNotContain("All 1 check pass.", html);
    }

    [Theory]
    [InlineData(1, "1 check needs attention; none has errors.")]
    [InlineData(2, "2 checks need attention; none has errors.")]
    public void WarningVerdictUsesCountAgreement(int count, string expected) {
        var report = CreateArea(count, CheckOutcome.Warning);
        Assert.Equal(expected, Wording.ReportVerdict(report));
    }

    [Theory]
    [InlineData(1, "No overall grade: 1 scored check has incomplete evidence. Not scored: Security.")]
    [InlineData(2, "No overall grade: some scored checks have incomplete evidence. Not scored: Security.")]
    public void IncompleteScoreNoteUsesCountAgreementInHtmlAndMarkdown(int count, string expected) {
        var report = CreateArea(count, CheckOutcome.Incomplete);
        // HTML renders its score caption alongside a score or completed-area meter. Keep a completed area in this
        // mixed-evidence fixture while the overall score remains unavailable because Security is incomplete.
        report.Domains[0].Checks.Add(new CheckAssessment {
            Key = "dns", Title = "DNS", Area = AnalysisArea.DNS, Outcome = CheckOutcome.Pass, Scored = true, Score = 100
        });
        report.Domains[0].Areas.Add(new AreaScore { Area = AnalysisArea.DNS, Checks = 1, Score = 100 });
        Assert.Equal(expected, Wording.ScoreNote(report));
        var html = new HtmlParser().ParseDocument(AssessmentHtmlReport.Render(report));
        var caption = Assert.Single(html.QuerySelectorAll(".hfx-as-posture-caption"));
        Assert.Equal(expected, caption.TextContent.Trim());
        Assert.Contains(expected, AssessmentMarkdownReport.Render(report));
    }

    [Theory]
    [InlineData(0, "Mail")]
    [InlineData(1, "Mail · and 1 more finding")]
    [InlineData(3, "Mail · and 3 more findings")]
    public void ActionSourceUsesCountAgreement(int additionalFindings, string expected) {
        var check = new CheckAssessment { Area = AnalysisArea.Mail, ErrorCount = 1, WarningCount = additionalFindings };
        Assert.Equal(expected, Wording.DoFirstSource(check));
    }

    private static DomainAssessmentReport CreateArea(int count, CheckOutcome outcome) {
        var report = new DomainAssessmentReport();
        var domain = new DomainAssessment { Domain = "example.test" };
        for (int index = 0; index < count; index++) {
            domain.Checks.Add(new CheckAssessment {
                Key = "check" + index, Title = "Check " + index, Area = AnalysisArea.Security,
                Outcome = outcome, Scored = outcome != CheckOutcome.Info,
                EvidenceComplete = outcome != CheckOutcome.Incomplete,
                Score = outcome == CheckOutcome.Pass ? 100 : null
            });
        }
        domain.Areas.Add(new AreaScore { Area = AnalysisArea.Security, Checks = count, Score = outcome == CheckOutcome.Pass ? 100 : null });
        report.Domains.Add(domain);
        return report;
    }
}
