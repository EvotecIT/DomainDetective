using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DnsClientX;

namespace DomainDetective.Tests;

[CollectionDefinition("Performance proxy environment", DisableParallelization = true)]
public class PerformanceProxyEnvironment { }

[Collection("Performance proxy environment")]
public class TestPerformanceReviewEvidence {
    [Fact]
    public async Task OptionalDnssecExceptionRetainsIncompleteMetadataEvidence() {
        var analysis = new DnsSecAnalysis {
            QueryDnsResponseOverride = (_, type, _) => type == (DnsRecordType)51
                ? throw new HttpRequestException("Synthetic optional metadata failure")
                : Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError })
        };
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.False(analysis.MetadataQueriesComplete);
        Assert.NotEmpty(analysis.MetadataQueryFailures);
    }

    [Fact]
    public async Task ProvidedCertificateEntryPointsMarkCompletedInspection() {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=fixture.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var analysis = new CertificateAnalysis { SkipRevocation = true, CaptureExtendedMetadata = false, CaptureCtMetadata = false };
        await analysis.AnalyzeCertificate(certificate);
        Assert.True(analysis.AnalysisComplete);
        Assert.True(Views.Converters.Convert(analysis).AnalysisComplete);
        await analysis.AnalyzeCertificateWithEnrichment(certificate);
        Assert.True(analysis.AnalysisComplete);
    }

    [Fact]
    public async Task TyposquattingDeadlineRetainsExplanatoryAssessment() {
        using var configuration = new DnsConfiguration {
            QueryDnsResponseOverride = async (_, _, ct) => {
                await Task.Delay(Timeout.Infinite, ct);
                return new DnsResponse();
            }
        };
        var analysis = new TyposquattingAnalysis { DnsConfiguration = configuration, AnalysisTimeout = TimeSpan.FromMilliseconds(50) };
        await analysis.Analyze("example.com", new InternalLogger());
        Assert.False(analysis.AnalysisComplete);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "TYPOSQUAT.Analysis.Incomplete");
    }

    [Fact]
    public async Task InfiniteHttpTimeoutStillHonorsAuxiliaryProtocolDeadline() {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        using var analysis = new CertificateAnalysis {
            Timeout = Timeout.InfiniteTimeSpan,
            ProtocolProbeTimeout = TimeSpan.FromMilliseconds(30),
            OutboundAddressResolver = async (_, ct) => {
                await Task.Delay(Timeout.Infinite, ct);
                return Array.Empty<IPAddress>();
            }
        };
        var probe = typeof(CertificateAnalysis).GetMethod("ProbeProtocolSupport", BindingFlags.NonPublic | BindingFlags.Instance)!;
        await (Task)probe.Invoke(analysis, new object[] { new Uri("https://example.com"), 443, new InternalLogger(), guard.Token })!;
        Assert.False(guard.IsCancellationRequested);
        Assert.False(analysis.ProtocolSupportComplete);
    }

    [Fact]
    public async Task StaticWebRetainsSuccessfulAddressFamilyWhenSiblingFails() {
        using var configuration = new DnsConfiguration {
            QueryDnsResponseOverride = (_, type, _) => Task.FromResult(type == DnsRecordType.A
                ? new DnsResponse { Status = DnsResponseCode.NoError, Answers = new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.123", TTL = 600 } } }
                : new DnsResponse { Status = DnsResponseCode.ServerFailure })
        };
        var analysis = new WebStaticScanAnalysis {
            DnsConfiguration = configuration,
            TlsProbeTimeout = TimeSpan.FromMilliseconds(1),
            RdapQueryTimeout = TimeSpan.FromMilliseconds(1)
        };
        var host = new WebStaticScanAnalysis.StaticHost { Host = "localhost" };
        analysis.Hosts[host.Host] = host;
        var enrich = typeof(WebStaticScanAnalysis).GetMethod("EnrichHostsAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await (Task)enrich.Invoke(analysis, new object[] { new InternalLogger(), guard.Token })!;
        Assert.Equal(new[] { "192.0.2.123" }, host.IpAddresses);
        Assert.Equal(600, host.ATtlMin);
        Assert.NotNull(host.DnsEnrichmentError);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SilentProxyConnectObservesCancellationAndClosesOwnedConnection(bool partialHeaders) {
        string[] names = { "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var analysis = new CertificateAnalysis();
        using var cancellation = new CancellationTokenSource();
        TcpClient? peer = null;
        Task<TcpClient>? work = null;
        try {
            foreach (string name in names) { Environment.SetEnvironmentVariable(name, null); }
            Environment.SetEnvironmentVariable("HTTPS_PROXY", $"http://127.0.0.1:{port}");
            var connect = typeof(CertificateAnalysis).GetMethod("ConnectWithProxy", BindingFlags.NonPublic | BindingFlags.Instance)!;
            work = (Task<TcpClient>)connect.Invoke(analysis, new object[] { "example.com", 443, cancellation.Token })!;
            peer = await listener.AcceptTcpClientAsync();
            if (partialHeaders) {
                var bytes = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection established\r\nProxy-Agent: waiting");
                await peer.GetStream().WriteAsync(bytes, 0, bytes.Length);
            }
            cancellation.Cancel();
            Assert.Same(work, await Task.WhenAny(work, Task.Delay(1500)));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => work);
        } finally {
            cancellation.Cancel();
            peer?.Dispose();
            listener.Stop();
            if (work != null) {
                try { (await work)?.Dispose(); }
                catch (OperationCanceledException) { }
                catch (IOException) { }
                catch (SocketException) { }
            }
            foreach (string name in names) { Environment.SetEnvironmentVariable(name, previous[name]); }
        }
    }
}
