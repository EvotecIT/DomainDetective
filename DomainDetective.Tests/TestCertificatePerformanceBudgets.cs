using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

[Collection("CtSharedState")]
public class TestCertificatePerformanceBudgets {
    public TestCertificatePerformanceBudgets() => CtLogAggregator.ResetSharedStateForTests();

    [Fact]
    public async Task CtDeadlineRetainsEntriesAndSourcesFromEarlierSuccessfulRequests() {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var analysis = new CertificateAnalysis {
            SkipRevocation = true, CaptureExtendedMetadata = false, CaptureCtMetadata = true,
            CtLookupTimeout = TimeSpan.FromMilliseconds(700)
        };
        string suffix = Guid.NewGuid().ToString("N");
        analysis.CtLogApiTemplates.Clear();
        analysis.CtLogApiTemplates.Add($"https://first-{suffix}.example.test/?sha256={{0}}");
        analysis.CtLogApiTemplates.Add($"https://second-{suffix}.example.test/?sha256={{0}}");
        var handler = new PartialCtHandler();
        analysis.CtLogs.HttpHandlerFactory = () => handler;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await analysis.AnalyzeCertificateWithEnrichment(certificate, guard.Token);
        Assert.False(analysis.CtLookupComplete);
        Assert.False(analysis.AnalysisComplete);
        Assert.True(analysis.PresentInCtLogs);
        Assert.Equal(11, Assert.Single(analysis.CtLogEntries).GetProperty("id").GetInt32());
        Assert.Equal(2, analysis.CtDiscoverySources.Count);
        Assert.Equal(2, handler.Calls);
        Assert.True(handler.CleanupObserved);
    }

    private sealed class PartialCtHandler : HttpMessageHandler {
        internal int Calls;
        internal bool CleanupObserved;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            if (Interlocked.Increment(ref Calls) == 1) {
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[{\"id\":11}]") };
            }
            try { await Task.Delay(Timeout.Infinite, cancellationToken); }
            finally { CleanupObserved = true; }
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task CtDeadlineRetainsCertificateAndNextInspectionResetsCoverage() {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var delayed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var analysis = new CertificateAnalysis {
            SkipRevocation = true, CaptureExtendedMetadata = false, CaptureCtMetadata = true,
            CtLookupTimeout = TimeSpan.FromMilliseconds(30), CtLogQueryOverride = _ => delayed.Task
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            await analysis.AnalyzeCertificateWithEnrichment(certificate, guard.Token);
            Assert.NotNull(analysis.Certificate);
            Assert.False(analysis.AnalysisComplete);
            Assert.False(analysis.CtLookupComplete);
            Assert.False(Views.Converters.Convert(analysis).CtLookupComplete);
            analysis.CtLogQueryOverride = _ => Task.FromResult("[]");
            await analysis.AnalyzeCertificateWithEnrichment(certificate, guard.Token);
            Assert.True(analysis.AnalysisComplete);
            Assert.True(analysis.CtLookupComplete);
        } finally { delayed.TrySetResult("[]"); }
    }

    [Fact]
    public async Task CallerCancellationStopsCtConsumptionAndLateResultCannotReplaceNewEvidence() {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var delayed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var analysis = new CertificateAnalysis {
            SkipRevocation = true, CaptureExtendedMetadata = false, CaptureCtMetadata = true,
            CtLookupTimeout = TimeSpan.FromSeconds(5), CtLogQueryOverride = _ => delayed.Task
        };
        using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        try {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeCertificateWithEnrichment(certificate, caller.Token));
            Assert.False(analysis.AnalysisComplete);
            analysis.CtLogQueryOverride = _ => Task.FromResult("[{\"id\":1}]");
            await analysis.AnalyzeCertificateWithEnrichment(certificate);
            delayed.TrySetResult("[]");
            await Task.Yield();
            Assert.True(analysis.CtLookupComplete);
            Assert.True(analysis.PresentInCtLogs);
            Assert.Single(analysis.CtLogEntries);
        } finally { delayed.TrySetResult("[]"); }
    }

    [Fact]
    public async Task CtDiscoveryStartsBeforeIndependentProtocolProbesFinish() {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var ctStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseProtocols = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int protocolCalls = 0;
        int protocolCompletions = 0;
        using var analysis = new CertificateAnalysis {
            SkipRevocation = true, CaptureExtendedMetadata = false,
            // Bound the unrelated optional OpenSSL phase inside the outer test guard.
            Timeout = TimeSpan.FromSeconds(5)
        };
        await analysis.AnalyzeCertificate(certificate);
        analysis.CaptureExtendedMetadata = true;
        analysis.CtLogQueryOverride = _ => { ctStarted.TrySetResult(true); return Task.FromResult("[]"); };
        analysis.OutboundAddressResolver = async (_, ct) => {
            Interlocked.Increment(ref protocolCalls);
            try {
                await releaseProtocols.Task.WaitWithCancellation(ct);
                return Array.Empty<IPAddress>();
            } finally { Interlocked.Increment(ref protocolCompletions); }
        };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var finalize = typeof(CertificateAnalysis).GetMethod("FinalizeCapturedCertificateAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var finalization = (Task)finalize.Invoke(analysis, new object[] { "https://127.0.0.1", 1, new InternalLogger(), guard.Token })!;
        try {
            await ctStarted.Task.WaitWithCancellation(guard.Token);
            Assert.Equal(4, protocolCalls);
            Assert.Equal(0, Volatile.Read(ref protocolCompletions));
        } finally {
            releaseProtocols.TrySetResult(true);
            await finalization;
        }
        Assert.Equal(4, protocolCompletions);
        Assert.True(analysis.CtLookupComplete);
    }

    [Fact]
    public async Task AuxiliaryVersionsOverlapAndTimeoutDoesNotMeanUnsupported() {
        var allEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int active = 0;
        int peak = 0;
        int calls = 0;
        using var analysis = new CertificateAnalysis {
            ProtocolProbeTimeout = TimeSpan.FromSeconds(5),
            OutboundAddressResolver = async (_, ct) => {
                int started = Interlocked.Increment(ref calls);
                int current = Interlocked.Increment(ref active);
                int previous;
                do { previous = peak; }
                while (current > previous && Interlocked.CompareExchange(ref peak, current, previous) != previous);
                if (started == 4) { allEntered.TrySetResult(true); }
                try {
                    await allEntered.Task.WaitWithCancellation(ct);
                    throw new TimeoutException("Synthetic resolver transport timeout");
                }
                finally { Interlocked.Decrement(ref active); }
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
