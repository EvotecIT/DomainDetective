using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public partial class TestCtLogAggregator {
    private const string CertificateFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Theory]
    [InlineData(CertificateCtEnrichmentProfile.Default, false)]
    [InlineData(CertificateCtEnrichmentProfile.Public, false)]
    [InlineData(CertificateCtEnrichmentProfile.Extended, false)]
    [InlineData(CertificateCtEnrichmentProfile.Default, true)]
    [InlineData(CertificateCtEnrichmentProfile.Public, true)]
    [InlineData(CertificateCtEnrichmentProfile.Extended, true)]
    public async Task InventoryProfilesPerformOneSupportedFingerprintLookup(CertificateCtEnrichmentProfile profile, bool metadataFallback) {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var sha = SHA256.Create();
        var fingerprint = BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", "").ToLowerInvariant();
        var handler = new SequenceHandler(new[] { CreateJsonResponse(HttpStatusCode.OK,
            CertificatePage(LogRow).Replace(CertificateFingerprint, fingerprint)) });
        var analysis = new CertificateAnalysis();
        CertificateInventoryCapture.ConfigureHttpsAnalysis(analysis, new CertificateInventoryCaptureOptions {
            CtProfile = profile, CaptureExtendedHttpsMetadata = true,
            EnablePassiveCtFallback = !metadataFallback, EnablePassiveCtMetadataFallback = metadataFallback,
            IncludeDefaultCtTemplate = true
        });
        Assert.Equal(CtLogAggregator.CrtShCertificateTemplate, Assert.Single(analysis.CtLogApiTemplates));
        // Exercise configured public CT acquisition without unrelated TLS/commercial enrichment.
        analysis.SkipRevocation = true;
        analysis.CaptureExtendedMetadata = false;
        analysis.CaptureTlsDetails = false;
        analysis.EnableCensysCtSource = false;
        analysis.EnableShodanCtSource = false;
        analysis.CtLogs.HttpHandlerFactory = () => handler;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await analysis.AnalyzeCertificateWithEnrichment(certificate, guard.Token);
        Assert.True(analysis.CtLookupComplete);
        Assert.True(analysis.PresentInCtLogs);
        Assert.Single(analysis.CtLogEntries);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task DefaultFingerprintSourceReadsCertificateLogTable() {
        var handler = new SequenceHandler(new[] { CreateJsonResponse(HttpStatusCode.OK, CertificatePage(LogRow)) });
        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        var result = await aggregator.QueryWithResultAsync(CertificateFingerprint);
        Assert.True(result.Complete);
        var entry = Assert.Single(result.Entries);
        Assert.Equal("2026-01-02T03:04:05.0000000+00:00", entry.GetProperty("entry_timestamp").GetString());
        Assert.Equal("https://log.example.test/ct/", entry.GetProperty("log_url").GetString());
        Assert.Equal("Synthetic & Co", entry.GetProperty("log_operator").GetString());
        Assert.Equal(123L, entry.GetProperty("entry_id").GetInt64());
        Assert.Equal(CertificateFingerprint, entry.GetProperty("sha256").GetString());
        Assert.DoesNotContain("output=json", Assert.Single(handler.RequestUrls));
    }

    [Fact]
    public async Task CertificateLogTableCanConfirmAnEmptyResult() {
        var handler = new SequenceHandler(new[] { CreateJsonResponse(HttpStatusCode.OK,
            CertificatePage("<TR><TD colspan=\"4\">No entries found</TD></TR>")) });
        var result = await new CtLogAggregator { HttpHandlerFactory = () => handler }.QueryWithResultAsync(CertificateFingerprint);
        Assert.True(result.Complete);
        Assert.Empty(result.Entries);
    }

    [Theory]
    [InlineData("wrong-certificate")]
    [InlineData("missing-table")]
    [InlineData("error-page")]
    [InlineData("truncated")]
    public async Task UnverifiedCertificatePagesDoNotEstablishAbsence(string state) {
        var page = CertificatePage(LogRow);
        page = state switch {
            "wrong-certificate" => page.Replace(CertificateFingerprint, new string('f', 64)),
            "missing-table" => page.Replace("Certificate Transparency", "Other metadata"),
            "error-page" => "<HTML><BODY>Temporary provider failure</BODY></HTML>",
            _ => page.Substring(0, page.IndexOf("</TABLE>", page.IndexOf("Timestamp", StringComparison.Ordinal), StringComparison.Ordinal))
        };
        var handler = new SequenceHandler(new[] { CreateJsonResponse(HttpStatusCode.OK, page) });
        var result = await new CtLogAggregator { HttpHandlerFactory = () => handler }.QueryWithResultAsync(CertificateFingerprint);
        Assert.False(result.Complete);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public async Task MalformedLogRowRetainsConfirmedRowsWithoutCachingIncompleteEvidence() {
        var handler = new SequenceHandler(new[] {
            CreateJsonResponse(HttpStatusCode.OK, CertificatePage(LogRow + "<TR><TD>malformed</TD></TR>")),
            CreateJsonResponse(HttpStatusCode.OK, CertificatePage(LogRow))
        });
        var aggregator = new CtLogAggregator { HttpHandlerFactory = () => handler };
        var first = await aggregator.QueryWithResultAsync(CertificateFingerprint);
        Assert.False(first.Complete);
        Assert.Single(first.Entries);
        var second = await aggregator.QueryWithResultAsync(CertificateFingerprint);
        Assert.True(second.Complete);
        Assert.Single(second.Entries);
        Assert.Equal(2, handler.RequestCount);
    }

    [Theory]
    [InlineData("<TR><TD>unfinished")]
    [InlineData("<TR><TD>2026-01-02 03:04:05 UTC</TD><TD>invalid</TD><TD>Operator</TD><TD>https://log.example.test/</TD></TR>")]
    public async Task IncompleteTableRowsCannotMakePartialEvidenceComplete(string malformed) {
        var handler = new SequenceHandler(new[] { CreateJsonResponse(HttpStatusCode.OK, CertificatePage(LogRow + malformed)) });
        var result = await new CtLogAggregator { HttpHandlerFactory = () => handler }.QueryWithResultAsync(CertificateFingerprint);
        Assert.False(result.Complete);
        Assert.Single(result.Entries);
    }

    private const string LogRow = "<TR><TD>2026-01-02&nbsp; <FONT class=\"small\">03:04:05 UTC</FONT></TD>" +
        "<TD>123</TD><TD>Synthetic &amp; Co</TD><TD>https://log.example.test/ct/</TD></TR>";

    private static string CertificatePage(string rows) =>
        "<HTML><BODY><TABLE><TR><TH class=\"outer\">Criteria</TH><TD class=\"outer\">SHA-256(Certificate) = '" +
        CertificateFingerprint + "'</TD></TR></TABLE><TABLE><TR><TH class=\"outer\">Certificate Transparency</TH>" +
        "<TD class=\"outer\"><DIV style=\"overflow-y:scroll;height:100px\"><TABLE class=\"identities\">" +
        "<TR><TH>Timestamp</TH><TH>Entry #</TH><TH>Log Operator</TH><TH>Log URL</TH></TR>" + rows +
        "</TABLE></DIV></TD></TR></TABLE></BODY></HTML>";
}
