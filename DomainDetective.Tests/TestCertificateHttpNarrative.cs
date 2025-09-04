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
        Assert.NotNull(analysis.Assessments);
        Assert.Equal(2, analysis.Assessments.Count);
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

    [Fact]
    public void HighlightsExpiredAndInvalidCertificates() {
        var analysis = new CertificateAnalysis {
            Subject = "expired.example",
            Url = "https://expired.example",
            IsReachable = true,
            IsValid = false,
            DaysToExpire = -1
        };

        typeof(CertificateAnalysis).GetProperty("IsExpired")!.SetValue(analysis, true);

        var sections = CertificateHttpNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("invalid"));
        Assert.Contains(sections.Highlights, h => h.Contains("expired"));
    }

    [Fact]
    public void HandlesNullCertificateAndEmptyAssessments() {
        var analysis = new CertificateAnalysis {
            Subject = "nocert.example",
            Url = "https://nocert.example",
            IsReachable = true,
            IsValid = true,
            Certificate = null!
        };

        var sections = CertificateHttpNarrative.Build(analysis, new List<Assessment>());
        Assert.Empty(sections.Details);
        Assert.Empty(sections.Positives);
        Assert.Empty(sections.Remediations);
    }

    [Fact]
    public void SplitsLargeAssessmentCollections() {
        var analysis = new CertificateAnalysis { Subject = "big.example" };
        for (var i = 0; i < 100; i++) {
            analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = CertificateHttpCodes.ChainValid, Message = "ok" });
            analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Error, Code = CertificateHttpCodes.FetchFailed, Message = "bad" });
        }

        var sections = CertificateHttpNarrative.Build(analysis, analysis.Assessments);
        Assert.Equal(200, analysis.Assessments.Count);
        Assert.Single(sections.Positives);
        Assert.Single(sections.Remediations);
    }
}
