using System.Collections.Generic;
using Xunit;

namespace DomainDetective.Tests;

public class TestWebTechVerificationCatalog
{
    [Fact]
    public void DnsTxt_GoogleSiteVerification_Detected()
    {
        var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var details = new List<TechDetectionDetail>();
        var txt = "google-site-verification=abc123";
        WebTechVerificationCatalog.ApplyDnsTxt(txt, set, details);
        Assert.Contains("Google Site Verification", set);
        Assert.Contains(details, d => d.Name == "Google Site Verification" && d.SourceKind == TechEvidenceKind.Dns);
    }

    [Fact]
    public void DnsTxt_Statuspage_Detected()
    {
        var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var details = new List<TechDetectionDetail>();
        var txt = "status-page-domain-verification=xyz";
        WebTechVerificationCatalog.ApplyDnsTxt(txt, set, details);
        Assert.Contains("Atlassian Statuspage", set);
        Assert.Contains(details, d => d.Name == "Atlassian Statuspage" && d.SourceKind == TechEvidenceKind.Dns);
    }
}

