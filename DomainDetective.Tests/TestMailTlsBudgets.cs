using System.Net;
using System.Net.Sockets;
using MailProtocol = DomainDetective.MailTlsAnalysis.MailProtocol;

namespace DomainDetective.Tests;

public class TestMailTlsBudgets {
    [Fact]
    public async Task StringHostsDeduplicateAfterEndpointNormalization() {
        int queries = 0;
        var analysis = new MailTlsAnalysis { OutboundAddressResolver = (_, _) => {
            Interlocked.Increment(ref queries);
            return Task.FromResult<IReadOnlyList<IPAddress>>(Array.Empty<IPAddress>());
        } };
        await analysis.AnalyzeServers(MailProtocol.Imap, new[] { "mail.example.test", "mail.example.test." }, 143, new InternalLogger());
        Assert.Equal(1, queries);
        Assert.Single(analysis.ServerResults);
    }
    [Theory]
    [InlineData(MailProtocol.Imap)]
    [InlineData(MailProtocol.Pop3)]
    public async Task RefusedConnectionIsNotOfferedAndDoesNotReportTlsFailure(MailProtocol protocol) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var analysis = new MailTlsAnalysis();
        await analysis.AnalyzeServer(protocol, new MailTransportEndpoint("mail.example.test", port) { ConnectAddress = IPAddress.Loopback }, new InternalLogger());
        Assert.Null(Assert.Single(analysis.ServerResults).Value.Certificate);
        Assert.Contains(analysis.Assessments, a => a.Code == "MAILTLS.Service.NotOffered");
        Assert.DoesNotContain(analysis.Assessments, a => a.Severity is AssessmentSeverity.Warning or AssessmentSeverity.Error);
    }

    [Fact]
    public async Task ResolutionTimeoutIsNotOfferedAndCallerCancellationStillPropagates() {
        var analysis = new MailTlsAnalysis { ConnectTimeout = TimeSpan.FromMilliseconds(50),
            OutboundAddressResolver = async (_, token) => {
                await Task.Delay(Timeout.Infinite, token);
                return Array.Empty<IPAddress>();
            } };
        await analysis.AnalyzeServer(MailProtocol.Imap, "mail.example.test", 143, new InternalLogger());
        Assert.Contains(analysis.Assessments, a => a.Code == "MAILTLS.Service.NotOffered");
        Assert.DoesNotContain(analysis.Assessments, a => a.Severity == AssessmentSeverity.Error);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeServer(MailProtocol.Imap, "mail.example.test", 143, new InternalLogger(), canceled.Token));
    }

    [Fact]
    public async Task EndpointProbesOverlapWithoutExceedingTheConfiguredCap() {
        int active = 0, peak = 0;
        var firstWave = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new MailTlsAnalysis { MaxConcurrency = 2,
            OutboundAddressResolver = async (_, token) => {
                int count = Interlocked.Increment(ref active);
                int old;
                do { old = Volatile.Read(ref peak); } while (count > old && Interlocked.CompareExchange(ref peak, count, old) != old);
                if (count == 2) { firstWave.TrySetResult(true); }
                try { await release.Task.WaitWithCancellation(token); }
                finally { Interlocked.Decrement(ref active); }
                return Array.Empty<IPAddress>();
            } };
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var run = analysis.AnalyzeServers(MailProtocol.Pop3, new[] { "one.example.test", "two.example.test", "three.example.test" }, 110, new InternalLogger(), guard.Token);
        try {
            await firstWave.Task.WaitWithCancellation(guard.Token);
            Assert.Equal(2, Volatile.Read(ref active));
        } finally { release.TrySetResult(true); }
        await run;
        Assert.Equal(2, peak);
        Assert.Equal(3, analysis.ServerResults.Count);
        Assert.Equal(3, analysis.Assessments.Count(a => a.Code == "MAILTLS.Service.NotOffered"));
    }
}
