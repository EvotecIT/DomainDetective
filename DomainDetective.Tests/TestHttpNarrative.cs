using System.Collections.Generic;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestHttpNarrative
{
    [Fact]
    public void BuildsNarrativeWithHighlightsAndPositives()
    {
        var analysis = new HttpAnalysis { Subject = "example.com" };
        typeof(HttpAnalysis).GetProperty("StatusCode")!.SetValue(analysis, 200);
        analysis.VisitedUrls.Add("http://example.com");
        analysis.VisitedUrls.Add("https://example.com");
        analysis.SecurityHeaders["Strict-Transport-Security"] = new SecurityHeader("Strict-Transport-Security", "max-age=31536000");
        analysis.SecurityHeaders["Content-Security-Policy"] = new SecurityHeader("Content-Security-Policy", "default-src 'self'");
        typeof(HttpAnalysis).GetProperty("HstsPresent")!.SetValue(analysis, true);
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = HttpCodes.SecureRedirect, Message = "redirects to https" });
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = HttpCodes.HstsPresent, Message = "hsts" });
        analysis.Assessments.Add(new Assessment { Severity = AssessmentSeverity.Info, Code = HttpCodes.CspPresent, Message = "csp" });

        var sections = HttpNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("200"));
        Assert.Contains(sections.Highlights, h => h.Contains("Redirect chain"));
        Assert.Contains(sections.Highlights, h => h.Contains("Security headers"));
        Assert.Contains(sections.Details, d => d.Contains("http://example.com"));
        Assert.Contains(sections.Details, d => d.Contains("https://example.com"));
        Assert.NotEmpty(sections.Positives);
    }

    [Fact]
    public void ProvidesPositiveAdvice()
    {
        var assessments = new List<Assessment>
        {
            new() { Severity = AssessmentSeverity.Info, Code = HttpCodes.SecureRedirect, Message = "redirect" },
            new() { Severity = AssessmentSeverity.Info, Code = HttpCodes.HstsPresent, Message = "hsts" },
            new() { Severity = AssessmentSeverity.Info, Code = HttpCodes.CspPresent, Message = "csp" }
        };
        var positives = RecommendationEngine.FromPositives(assessments);
        Assert.Contains(positives, p => p.Code == HttpCodes.SecureRedirect);
        Assert.Contains(positives, p => p.Code == HttpCodes.HstsPresent);
        Assert.Contains(positives, p => p.Code == HttpCodes.CspPresent);
    }
}
