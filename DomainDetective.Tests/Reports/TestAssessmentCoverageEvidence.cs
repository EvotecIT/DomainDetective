using System.Text.RegularExpressions;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Views;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentCoverageEvidence {
    [Theory]
    [InlineData(false, false, 1, 0)]
    [InlineData(true, false, 0, 0)]
    [InlineData(false, true, 0, 1)]
    [InlineData(true, true, 0, 1)]
    public void CoverageBarsCountCompletedPassesAndRetainKnownFindings(bool incomplete, bool warning, int passed, int failed) {
        // A discovered MX with an unfinished address lookup is a reachable partial result.
        var view = new MxInfo {
            Subject = "example.test", Check = HealthCheckType.MX,
            MxRecordExists = true, MxRecords = new[] { "10 mail.example.test" },
            AddressQueryFailed = incomplete, Status = incomplete ? "Incomplete" : "OK",
            Assessments = warning ? new[] {
                new Assessment { Severity = AssessmentSeverity.Warning, Code = "MX.Fixture.Warning", Message = "A known MX warning." }
            } : Array.Empty<Assessment>()
        };
        var control = new MxInfo {
            Subject = "control.test", Check = HealthCheckType.MX,
            MxRecordExists = true, MxRecords = new[] { "10 mail.control.test" }, Status = "OK"
        };
        var report = DomainAssessmentBuilder.Build(new object[] { view, control });
        var check = Assert.Single(Assert.Single(report.Domains, domain => domain.Domain == "example.test").Checks);
        Assert.Equal(!incomplete, check.EvidenceComplete);
        Assert.Equal(failed, check.WarningCount);
        if (incomplete) {
            Assert.Null(check.Score);
        }

        var html = AssessmentHtmlReport.Render(report);
        var cells = Regex.Matches(html, @"<a\b[^>]*\bclass=""hfx-as-cell""[^>]*>[\s\S]*?</a>").Cast<Match>().ToArray();
        Assert.Equal(2, cells.Length);
        var cell = Assert.Single(cells, match => match.Value.Contains("href=\"#domain-example-test-mx\"")).Value;
        var passingControl = Assert.Single(cells, match => match.Value.Contains("href=\"#domain-control-test-mx\"")).Value;
        Assert.Contains("class=\"is-pass\" style=\"flex-grow: 1;\"", passingControl);
        if (passed + failed == 0) {
            Assert.Contains("class=\"hfx-as-progress is-empty\"", cell);
            Assert.DoesNotContain("class=\"is-pass\"", cell);
        } else {
            Assert.Contains($"class=\"is-pass\" style=\"flex-grow: {passed};\"", cell);
            Assert.Contains($"class=\"is-fail\" style=\"flex-grow: {failed};\"", cell);
        }
        if (incomplete && !warning) {
            Assert.Contains(">Incomplete</span>", cell);
        }
    }
}
