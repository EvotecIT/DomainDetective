using DomainDetective.Narratives;
using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestCertificateHttpNarrative {
    [Fact]
    public void BuildsNarrativeWithHighlightsAndPositives() {
        var analysis = new CertificateAnalysis {
            Subject = "example.com",
            Url = "https://example.com",
            IsReachable = true,
            IsValid = true,
            DaysToExpire = 30
        };
        analysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Info,
            Code = CertificateHttpCodes.ChainValid,
            Message = "Chain valid"
        });
        analysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Info,
            Code = CertificateHttpCodes.ContentTypeValid,
            Message = "Content type ok"
        });
        var sections = CertificateHttpNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("chain is valid"));
        Assert.Contains(sections.Highlights, h => h.Contains("expires in"));
        Assert.NotEmpty(sections.Positives);
    }

    [Fact]
    public void ProvidesPositiveAdvice() {
        var assessments = new List<Assessment> {
            new() { Severity = AssessmentSeverity.Info, Code = CertificateHttpCodes.ChainValid, Message = "Chain valid" },
            new() { Severity = AssessmentSeverity.Info, Code = CertificateHttpCodes.ContentTypeValid, Message = "Content type ok" }
        };
        var positives = RecommendationEngine.FromPositives(assessments);
        Assert.Contains(positives, p => p.Code == CertificateHttpCodes.ChainValid);
        Assert.Contains(positives, p => p.Code == CertificateHttpCodes.ContentTypeValid);
    }
}
