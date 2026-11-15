using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DomainDetective;
using DomainDetective.DesiredState;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestDesiredStateParity
{
    [Fact]
    public void DesiredAndBestPracticeFindingsRemainDistinctInAllFormats()
    {
        var domain = "example.org";
        var desiredWarnings = 2;
        var desiredErrors = 1;
        var bestWarnings = 3;
        var bestErrors = 4;

        var view = new DesiredStateInfo
        {
            Subject = domain,
            Mode = DesiredStateMode.BestPracticesForUnspecified,
            Conforms = false,
            WarningCount = desiredWarnings,
            ErrorCount = desiredErrors,
            BestPracticeWarningCount = bestWarnings,
            BestPracticeErrorCount = bestErrors,
            DesiredAssessments = CreateAssessments(domain, "DesiredState", AssessmentSeverity.Warning, desiredWarnings)
                .Concat(CreateAssessments(domain, "DesiredState", AssessmentSeverity.Error, desiredErrors))
                .ToArray(),
            BestPracticeAssessments = CreateAssessments(domain, "SPF", AssessmentSeverity.Warning, bestWarnings)
                .Concat(CreateAssessments(domain, "SPF", AssessmentSeverity.Error, bestErrors))
                .ToArray(),
            References = new[] { "https://example.org/reference" }
        };

        var report = DomainAssessmentBuilder.Build(new object[] { view });
        var check = Assert.Single(Assert.Single(report.Domains).Checks);
        Assert.Contains(check.Findings, finding => finding.Code == "DesiredState.Error.1" && finding.Message == "Test DesiredState Error #1");
        Assert.Contains(check.Evidence, evidence => evidence.Title == "Best-practice findings" && evidence.Rows.Any(row => row.Contains("Test SPF Error #1")));
        var directory = Path.Combine(Path.GetTempPath(), "dd-desired-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var paths = new[] { Path.Combine(directory, "report.html"), Path.Combine(directory, "report.md"), Path.Combine(directory, "report.docx"), Path.Combine(directory, "report.xlsx") };
            AssessmentHtmlReport.Generate(paths[0], report);
            AssessmentMarkdownReport.Generate(paths[1], report);
            AssessmentWordReport.Generate(paths[2], report);
            AssessmentExcelReport.Generate(paths[3], report);
            foreach (var path in paths) {
                string text = ReportArtifactText.Read(path);
                Assert.Contains("Test DesiredState Error #1", text);
                Assert.Contains("Test DesiredState Warning #1", text);
                Assert.Contains("Test SPF Error #1", text);
            }
        } finally { Directory.Delete(directory, true); }
    }

    private static Assessment[] CreateAssessments(string domain, string category, AssessmentSeverity severity, int count) {
        return Enumerable.Range(1, count).Select(i => new Assessment {
            Severity = severity, Category = category, Target = domain,
            Code = $"{category}.{severity}.{i}", Message = $"Test {category} {severity} #{i}"
        }).ToArray();
    }
}
