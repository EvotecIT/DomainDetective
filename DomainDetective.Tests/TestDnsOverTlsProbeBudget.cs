using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective.Definitions;
using DomainDetective.DesiredState;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnsOverTlsProbeBudget {
    [Fact]
    public async Task IndependentEndpointsUseBoundedWorkers() {
        var analysis = CreateAnalysis(6);
        analysis.QueryConcurrency = 2;
        int active = 0, peak = 0, calls = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.ProbeOverride = async (_, _, _, _, token) => {
            int now = Interlocked.Increment(ref active);
            peak = Math.Max(peak, now);
            if (Interlocked.Increment(ref calls) == 2) entered.TrySetResult(true);
            try { await release.Task; token.ThrowIfCancellationRequested(); }
            finally { Interlocked.Decrement(ref active); }
            return new DnsOverTlsEndpointResult { Outcome = DnsOverTlsProbeOutcome.TimedOut, Error = "Controlled timeout." };
        };
        Task run = analysis.Analyze("example.test", new InternalLogger());
        try { Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000))); }
        finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(2, peak);
        Assert.Equal(6, calls);
        Assert.Equal(6, analysis.ServerResults.Count);
        Assert.All(analysis.ServerResults.Values, result => Assert.True(result.Attempted));
        Assert.DoesNotContain(analysis.Assessments, item => item.Code == DnsOverTlsCodes.NotSupported);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BudgetRetainsUnattemptedEndpointsAndCallerCancellationPropagates(bool cancelCaller) {
        var analysis = CreateAnalysis(6);
        analysis.QueryConcurrency = 1;
        analysis.AnalysisTimeout = cancelCaller ? TimeSpan.FromSeconds(5) : TimeSpan.FromMilliseconds(100);
        int active = 0;
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        analysis.ProbeOverride = async (_, _, _, _, token) => {
            Interlocked.Increment(ref active); entered.TrySetResult(true);
            try { await Task.Delay(Timeout.Infinite, token); return new DnsOverTlsEndpointResult(); }
            finally { Interlocked.Decrement(ref active); }
        };
        using var caller = new CancellationTokenSource();
        Task run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(3000)));
        if (cancelCaller) {
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        } else {
            await run;
            Assert.Equal(6, analysis.ServerResults.Count);
            Assert.Single(analysis.ServerResults.Values, result => result.Attempted);
            Assert.All(analysis.ServerResults.Values, result => Assert.Equal(DnsOverTlsProbeOutcome.BudgetExhausted, result.Outcome));
            Assert.False(analysis.CoverageComplete);
            var summary = Converters.Convert(analysis);
            Assert.Equal(1, summary.TotalChecked);
        }
        Assert.Equal(0, active);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualConnectAndTlsFailureRetainDifferentStages(bool handshakeFailure) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var fixture = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task peer = Task.CompletedTask;
        if (!handshakeFailure) listener.Stop();
        else peer = Task.Run(async () => {
            using var client = await listener.AcceptTcpClientAsync().WaitWithCancellation(fixture.Token);
            using var stream = client.GetStream();
            byte[] header = new byte[5]; await ReadFully(stream, header, fixture.Token);
            await ReadFully(stream, new byte[(header[3] << 8) | header[4]], fixture.Token);
            byte[] alert = { 21, 3, 3, 0, 2, 2, 40 };
            await stream.WriteAsync(alert, 0, alert.Length, fixture.Token);
            await release.Task.WaitWithCancellation(fixture.Token);
        });
        try {
            var analysis = CreateAnalysis(1, loopback: true); analysis.Port = port;
            await analysis.Analyze("example.test", new InternalLogger(), fixture.Token);
            var result = Assert.Single(analysis.ServerResults.Values);
            Assert.False(result.Supported);
            Assert.Equal(handshakeFailure ? "TLS handshake" : "connect", result.FailureStage);
            Assert.Equal(handshakeFailure ? DnsOverTlsProbeOutcome.HandshakeFailed : DnsOverTlsProbeOutcome.ConnectionRefused, result.Outcome);
            Assert.DoesNotContain(analysis.Assessments, item => item.Code == DnsOverTlsCodes.NotSupported && item.Severity == AssessmentSeverity.Warning);
        } finally { release.TrySetResult(true); listener.Stop(); await peer; }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TlsAloneDoesNotEstablishDnsOverTlsSupport(bool validDnsResponse) {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=ns.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var fixture = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task peer = Task.Run(async () => {
            for (int i = 0; i < 2; i++) {
                using var client = await listener.AcceptTcpClientAsync().WaitWithCancellation(fixture.Token);
                using var tls = new SslStream(client.GetStream(), false);
                await tls.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false).WaitWithCancellation(fixture.Token);
                if (i == 0) continue;
                byte[] length = new byte[2]; await ReadFully(tls, length, fixture.Token);
                byte[] query = new byte[(length[0] << 8) | length[1]]; await ReadFully(tls, query, fixture.Token);
                byte[] response = validDnsResponse ? query : new byte[2];
                if (validDnsResponse) { response[2] |= 0x84; response[3] = 0; }
                byte[] size = { (byte)(response.Length >> 8), (byte)response.Length };
                await tls.WriteAsync(size, 0, size.Length, fixture.Token);
                await tls.WriteAsync(response, 0, response.Length, fixture.Token);
            }
        });
        try {
            var analysis = CreateAnalysis(1, loopback: true);
            analysis.Port = ((IPEndPoint)listener.LocalEndpoint).Port;
            analysis.Timeout = TimeSpan.FromSeconds(10);
            await analysis.Analyze("example.test", new InternalLogger(), fixture.Token);
            var result = Assert.Single(analysis.ServerResults.Values);
            Assert.True(result.TlsHandshakeSucceeded);
            Assert.Equal(validDnsResponse, result.Supported);
            Assert.Equal(validDnsResponse, result.DnsExchangeVerified);
            Assert.False(result.CertificateValid); // Protocol support is separate from certificate trust.
            Assert.Contains(analysis.Assessments, item => item.Code == DnsOverTlsCodes.CertificateInvalid);
            Assert.Equal(1, Converters.Convert(analysis).InvalidCertificateCount);
            if (!validDnsResponse) Assert.Equal("DNS exchange", result.FailureStage);
            await peer;
        } finally { fixture.Cancel(); listener.Stop(); try { await peer; } catch (OperationCanceledException) { } }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AddressDiscoveryFailureOrScanCapCannotReportCompleteCoverage(bool cap) {
        var analysis = CreateAnalysis(cap ? 3 : 1);
        analysis.MaxServersToProbe = cap ? 2 : 12;
        if (!cap) {
            analysis.QueryDnsOverride = (_, type) => type switch {
                DnsRecordType.NS => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } }),
                DnsRecordType.A => Task.FromResult(new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" } }),
                _ => throw new TimeoutException("Controlled IPv6 discovery timeout.")
            };
        }
        analysis.ProbeOverride = (_, _, _, _, _) => Task.FromResult(new DnsOverTlsEndpointResult { Supported = true });
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.False(analysis.CoverageComplete);
        Assert.Equal(cap ? 2 : 1, analysis.ServerResults.Count);
        Assert.Equal(cap ? 3 : 1, analysis.DiscoveredEndpointCount);
        if (!cap) Assert.Contains("ns.example.test AAAA", analysis.DiscoveryErrors.Keys);
        Assert.Contains(analysis.Assessments, item => item.Code == DnsOverTlsCodes.CoverageIncomplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExplicitSupportPolicyCannotConformWithEmptyDiscovery(bool all) {
        var health = new DomainHealthCheck();
        health.DnsOverTlsAnalysis.QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>());
        await health.DnsOverTlsAnalysis.Analyze("example.test", new InternalLogger());
        var policy = new DesiredStateProfile { DnsOverTls = new DesiredStateDnsOverTlsPolicy {
            RequireAnySupported = !all, RequireAllSupported = all
        }};
        var result = DesiredStateEvaluator.Evaluate("example.test", health, policy, MailDomainClassificationCategory.SendingAndReceiving);
        Assert.False(result.Conforms);
    }

    [Fact]
    public async Task RequireAllSupportCannotConformWhenScanCapOmittedAnEndpoint() {
        var health = new DomainHealthCheck();
        var analysis = CreateAnalysis(2); analysis.MaxServersToProbe = 1;
        analysis.ProbeOverride = (_, _, _, _, _) => Task.FromResult(new DnsOverTlsEndpointResult { Supported = true });
        // The public analysis object is shared by Verify and desired-state evaluation.
        health.DnsOverTlsAnalysis.QueryDnsOverride = (_, type) => Task.FromResult(type switch {
            DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } },
            DnsRecordType.A => new[] { new DnsAnswer { Type = type, DataRaw = "192.0.2.1" }, new DnsAnswer { Type = type, DataRaw = "192.0.2.2" } },
            _ => Array.Empty<DnsAnswer>()
        });
        health.DnsOverTlsAnalysis.MaxServersToProbe = 1;
        health.DnsOverTlsAnalysis.ProbeOverride = analysis.ProbeOverride;
        await health.DnsOverTlsAnalysis.Analyze("example.test", new InternalLogger());
        var result = DesiredStateEvaluator.Evaluate("example.test", health,
            new DesiredStateProfile { DnsOverTls = new DesiredStateDnsOverTlsPolicy { RequireAllSupported = true } },
            MailDomainClassificationCategory.SendingAndReceiving);
        Assert.False(result.Conforms);
    }

    private static async Task ReadFully(System.IO.Stream stream, byte[] buffer, CancellationToken token) {
        int offset = 0;
        while (offset < buffer.Length) {
            int read = await stream.ReadAsync(buffer, offset, buffer.Length - offset, token);
            if (read == 0) throw new System.IO.EndOfStreamException();
            offset += read;
        }
    }

    private static DnsOverTlsAnalysis CreateAnalysis(int count, bool loopback = false) => new() {
        QueryDnsOverride = (name, type) => Task.FromResult(type switch {
            DnsRecordType.NS => new[] { new DnsAnswer { Type = type, DataRaw = "ns.example.test" } },
            DnsRecordType.A => Enumerable.Range(1, count).Select(i => new DnsAnswer {
                Type = type, DataRaw = loopback ? "127.0.0.1" : $"192.0.2.{i}"
            }).ToArray(),
            _ => Array.Empty<DnsAnswer>()
        })
    };
}
