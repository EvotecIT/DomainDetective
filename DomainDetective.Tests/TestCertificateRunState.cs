using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public class TestCertificateRunState {
    [Fact]
    public async Task FailedReuseCannotExportThePreviousCertificate() {
        using var certificate = MakeCertificate("old.example");
        var analysis = new CertificateAnalysis { CaptureExtendedMetadata = false, PreferTlsHandshakeOnlyProbe = true, Timeout = TimeSpan.FromSeconds(2) };
        await analysis.AnalyzeCertificate(certificate);
        var previousOwned = analysis.Certificate!;
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        await analysis.AnalyzeUrl("https://127.0.0.1", port, new InternalLogger());
        Assert.False(analysis.IsReachable);
        Assert.Null(analysis.Certificate);
        Assert.Empty(analysis.Chain);
        Assert.Equal(0, analysis.DaysToExpire);
        Assert.Empty(analysis.ExtendedKeyUsageOids);
        Assert.Null(DomainDetective.Views.Converters.Convert(analysis).CertificateSubject);
        Assert.ThrowsAny<CryptographicException>(() => previousOwned.GetRawCertData());
        Assert.NotEmpty(certificate.GetRawCertData());
    }

    [Fact]
    public async Task ProvidedCertificateDoesNotQueryCtUnlessEnrichmentIsExplicit() {
        using var certificate = MakeCertificate("offline.example");
        int requests = 0;
        var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => { Interlocked.Increment(ref requests); return Task.FromResult("[{\"id\":1}]"); } };
        await analysis.AnalyzeCertificate(certificate);
        Assert.Equal(0, requests);
        Assert.False(analysis.PresentInCtLogs);
        Assert.Empty(analysis.CtLogEntries);
    }

    [Fact]
    public async Task ExplicitEnrichmentIsSeparateAndReuseClearsCtEvidence() {
        using var certificate = MakeCertificate("enriched.example");
        using var analysis = new CertificateAnalysis { SkipRevocation = true, CtLogQueryOverride = _ => Task.FromResult("[{\"id\":1}]") };
        await analysis.AnalyzeCertificateWithEnrichment(certificate);
        Assert.True(analysis.PresentInCtLogs);
        Assert.True(analysis.ChainValidationPerformed);
        Assert.False(analysis.HostnameValidationPerformed);
        await analysis.AnalyzeCertificate(analysis.Certificate!);
        Assert.False(analysis.PresentInCtLogs);
        Assert.Empty(analysis.CtLogEntries);
        Assert.False(analysis.ChainValidationPerformed);
        var converted = DomainDetective.Views.Converters.Convert(analysis);
        Assert.Contains("chain not assessed", converted.Summary);
        Assert.Contains("host not assessed", converted.Summary);
        Assert.Contains(converted.Highlights, item => item.Contains("trust was not assessed"));
        Assert.True(converted.ProvidedCertificateInspection);
    }

    [Fact]
    public async Task DisposalReleasesOnlyLibraryCreatedCertificates() {
        using var supplied = MakeCertificate("supplied.example");
        var analysis = new CertificateAnalysis();
        await analysis.AnalyzeCertificate(supplied);
        var ownedLeaf = analysis.Certificate!;
        var ownedChain = Assert.Single(analysis.Chain);
        analysis.Certificate = supplied;
        analysis.Chain.Add(supplied);
        analysis.Dispose();
        analysis.Dispose();
        Assert.NotEmpty(supplied.GetRawCertData());
        Assert.ThrowsAny<CryptographicException>(() => ownedLeaf.GetRawCertData());
        Assert.ThrowsAny<CryptographicException>(() => ownedChain.GetRawCertData());
    }

    private static X509Certificate2 MakeCertificate(string name) {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }
}
