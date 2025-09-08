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
    public void BasicHeadingsAndReferencesArePresent_AndDomainsColumnCaps()
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
            WordCompositionReport.Generate(
                tmp,
                new List<object> { spfView },
                ReportScope.Minimal,
                showInfoFindings: false,
                narrativePlacement: NarrativePlacement.Auto,
                titleOverride: "Unit Test Report");

            Assert.True(File.Exists(tmp));
            Assert.True(new FileInfo(tmp).Length > 0);

            using var zip = ZipFile.OpenRead(tmp);
            var docEntry = zip.Entries.First(e => e.FullName.Equals("word/document.xml", StringComparison.OrdinalIgnoreCase));
            using var stream = docEntry.Open();
            using var reader = new StreamReader(stream);
            var xml = reader.ReadToEnd();

            // Headings
            Assert.Contains("Executive Summary", xml);
            Assert.Contains("Overview", xml);
            Assert.Contains("All References", xml);

            // Domains column capping: expect "+2 more" when 8 targets and cap=6
            Assert.Contains("+2 more", xml);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }
}
