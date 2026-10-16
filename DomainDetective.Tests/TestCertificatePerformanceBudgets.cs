using System.Net;
using System.Reflection;

namespace DomainDetective.Tests;

public class TestCertificatePerformanceBudgets {
    [Fact]
    public async Task AuxiliaryVersionsOverlapAndTimeoutDoesNotMeanUnsupported() {
        int active = 0;
        int peak = 0;
        int calls = 0;
        using var analysis = new CertificateAnalysis {
            ProtocolProbeTimeout = TimeSpan.FromMilliseconds(30),
            OutboundAddressResolver = async (_, ct) => {
                Interlocked.Increment(ref calls);
                int current = Interlocked.Increment(ref active);
                int previous;
                do { previous = peak; }
                while (current > previous && Interlocked.CompareExchange(ref peak, current, previous) != previous);
                try { await Task.Delay(Timeout.Infinite, ct); }
                finally { Interlocked.Decrement(ref active); }
                return Array.Empty<IPAddress>();
            }
        };
        var probe = typeof(CertificateAnalysis).GetMethod("ProbeProtocolSupport", BindingFlags.NonPublic | BindingFlags.Instance)!;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await (Task)probe.Invoke(analysis, new object[] { new Uri("https://example.com"), 443, new InternalLogger(), guard.Token })!;
        Assert.Equal(4, calls);
        Assert.Equal(4, peak);
        Assert.Equal(0, active);
        Assert.False(analysis.ProtocolSupportComplete);
        Assert.False(analysis.LegacyProtocolSupportComplete);
        var view = Views.Converters.Convert(analysis);
        Assert.False(view.ProtocolSupportComplete);
        Assert.False(view.LegacyProtocolSupportComplete);
    }

    [Fact]
    public async Task WholeCertificateBudgetStopsOwnedResolutionAndRetainsIncompleteEvidence() {
        bool finished = false;
        using var analysis = new CertificateAnalysis {
            AnalysisTimeout = TimeSpan.FromMilliseconds(50),
            PreferTlsHandshakeOnlyProbe = true,
            CaptureExtendedMetadata = false,
            OutboundAddressResolver = async (_, ct) => {
                try { await Task.Delay(Timeout.Infinite, ct); }
                finally { finished = true; }
                return Array.Empty<IPAddress>();
            }
        };
        await analysis.AnalyzeUrl("https://example.com", 443, new InternalLogger());
        Assert.True(finished);
        Assert.False(analysis.AnalysisComplete);
        Assert.Null(analysis.Certificate);
        Assert.Equal(CertificateFailureKind.Timeout, analysis.FailureKind);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "CERT.Analysis.Incomplete");
    }
}
