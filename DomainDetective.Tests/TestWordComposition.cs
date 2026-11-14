using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;
using DomainDetective.Views;

namespace DomainDetective.Tests;

public class TestWordComposition
{
    [Fact]
    public void AssessmentWordRetainsEveryAffectedFindingTarget()
    {
        // Build a minimal SPF view with RFC reference and many targets for a single warning code
        var assessments = new List<Assessment>();
        for (int i = 1; i <= 8; i++)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Category = "SPF",
                Target = $"d{i}.example.com",
                Code = SpfCodes.QueryFailed,
                Message = "SPF DNS query failed"
            });
        }

        var spfView = new SpfRecordInfo
        {
            Check = HealthCheckType.SPF,
            Area = AnalysisArea.Mail,
            Subject = "example.com",
            SpfRecord = "v=spf1 -all",
            Assessments = assessments,
            Recommendations = RecommendationEngine.FromProblems(assessments),
            Positives = RecommendationEngine.FromPositives(assessments),
            References = new[] { "https://datatracker.ietf.org/doc/html/rfc7208" }
        };

        var tmp = Path.Combine(Path.GetTempPath(), $"dd-word-{Guid.NewGuid():N}.docx");
        try
        {
            AssessmentWordReport.Generate(tmp, DomainAssessmentBuilder.Build(new object[] { spfView },
                new DomainAssessmentOptions { Title = "Unit Test Report" }));

            Assert.True(File.Exists(tmp));
            Assert.True(new FileInfo(tmp).Length > 0);

            var xml = DomainDetective.Tests.Reports.ReportArtifactText.Read(tmp);
            Assert.Contains("SPF DNS query failed", xml);
            Assert.Contains(SpfCodes.QueryFailed, xml);

            // Grouping duplicate findings must retain every affected target.
            for (int i = 1; i <= 8; i++) { Assert.Contains($"d{i}.example.com", xml); }
            Assert.DoesNotContain("[Company name]", xml);
            Assert.DoesNotContain("No table of contents entries found.", xml);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

}
