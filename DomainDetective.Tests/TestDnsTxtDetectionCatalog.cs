using System.Collections.Generic;
using DomainDetective.Providers.Dns;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsTxtDetectionCatalog {
    [Fact]
    public void BingVerification_WithLeadingZeroVariant_StaysInSyncAcrossConsumers() {
        const string txt = "\"msvalidate.01=abc123\"";

        var signalMatch = DnsTxtSignalDetector.Detect(new[] { txt });
        Assert.True(signalMatch.Signals.HasFlag(DnsTxtSignals.BingWebmasterVerification));

        var apps = DetectedDnsApplicationCatalog.DetectTxt(txt);
        Assert.Contains(apps, app => app.Id == "bing-webmaster" && app.Category == DetectedDnsAppCategory.Analytics);

        var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var details = new List<TechDetectionDetail>();
        WebTechVerificationCatalog.ApplyDnsTxt(txt, set, details);
        Assert.Contains("Bing Site Verification", set);
        Assert.Contains(details, detail => detail.Name == "Bing Site Verification" && detail.SourceKind == TechEvidenceKind.Dns);
    }

    [Fact]
    public void KnownVerificationTokens_AreTreatedAsSafeByMalwareDetector() {
        var bingResult = DnsTxtMalwareDetector.Detect(new[] { ("@", "\"msvalidate.01=abc123\"") });
        var statuspageResult = DnsTxtMalwareDetector.Detect(new[] { ("@", "\"status-page-domain-verification=xyz\"") });

        Assert.Empty(bingResult.Findings);
        Assert.Empty(statuspageResult.Findings);
    }
}
