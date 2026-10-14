using System.Net;
using System.Net.Sockets;
using System.IO;
using MailProtocol = DomainDetective.MailTlsAnalysis.MailProtocol;

namespace DomainDetective.Tests;

public class TestMailTlsBudgets {
    [Theory]
    [InlineData(MailProtocol.Smtp)]
    [InlineData(MailProtocol.Imap)]
    [InlineData(MailProtocol.Pop3)]
    public async Task AuxiliaryVersionProbesPerformTheMailStartTlsExchange(MailProtocol protocol) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        int prepared = 0;
        var server = Task.Run(async () => {
            for (int i = 0; i < 3; i++) {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync(protocol == MailProtocol.Smtp ? "220 mail.example.test" : protocol == MailProtocol.Imap ? "* OK ready" : "+OK ready");
                string? command = await reader.ReadLineAsync().WaitWithCancellation(guard.Token);
                if (protocol == MailProtocol.Smtp) {
                    Assert.StartsWith("EHLO ", command);
                    await writer.WriteLineAsync("250 STARTTLS");
                } else if (protocol == MailProtocol.Imap) {
                    Assert.Equal("A1 CAPABILITY", command);
                    await writer.WriteLineAsync("* CAPABILITY STARTTLS\r\nA1 OK");
                } else {
                    Assert.Equal("CAPA", command);
                    await writer.WriteLineAsync("+OK\r\nSTLS\r\n.");
                }
                Assert.Equal(protocol == MailProtocol.Imap ? "A2 STARTTLS" : protocol == MailProtocol.Pop3 ? "STLS" : "STARTTLS",
                    await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                await writer.WriteLineAsync(protocol == MailProtocol.Smtp ? "220 Begin TLS" : protocol == MailProtocol.Imap ? "A2 OK" : "+OK");
                Interlocked.Increment(ref prepared);
                // A local runtime may reject a disabled TLS version before sending ClientHello.
                // Either outcome is after the required mail exchange; no certificate/key is needed here.
                await stream.ReadAsync(new byte[1], 0, 1, guard.Token);
            }
        });
        try {
            var analysis = new MailTlsAnalysis();
            var result = new MailTlsAnalysis.TlsResult { Protocol = System.Security.Authentication.SslProtocols.Tls12 };
            var probe = typeof(MailTlsAnalysis).GetMethod("ProbeProtocolSupport", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            await (Task)probe.Invoke(analysis, new object[] { protocol,
                new MailTransportEndpoint("mail.example.test", port) { ConnectAddress = IPAddress.Loopback }, result, guard.Token })!;
            Assert.Equal(3, Volatile.Read(ref prepared));
            Assert.True(result.ProtocolSupportComplete);
            Assert.True(result.SupportsTls12);
        } finally {
            guard.Cancel();
            listener.Stop();
            try { await server; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
            catch (SocketException) when (guard.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyTlsPolicyRequiresCompletedSupportProbes(bool completed) {
        using var health = new DomainHealthCheck();
        health.ImapTlsAnalysis.ServerResults["mail.example.test:143"] = new MailTlsAnalysis.TlsResult {
            ProtocolSupportComplete = completed, CertificateValid = true, HostnameMatch = true, GradeLevel = GradeLevel.B
        };
        var result = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
            new DomainDetective.DesiredState.DesiredStateProfile {
                ImapTls = new DomainDetective.DesiredState.DesiredStateMailTlsPolicy { DisallowLegacyProtocols = true }
            });
        Assert.Equal(completed, result.Conforms);
        Assert.Equal(!completed, result.Assessments.Any(item => item.Code == "DesiredState.MailTls.ProtocolSupport.QueryFailed"));
    }

    [Fact]
    public async Task ExpiredProtocolProbeBudgetPreservesKnownSupportAndLeavesOtherVersionsUnknown() {
        var pending = new TaskCompletionSource<IReadOnlyList<IPAddress>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var analysis = new MailTlsAnalysis { OutboundAddressResolver = (_, _) => { started.TrySetResult(true); return pending.Task; } };
        var result = new MailTlsAnalysis.TlsResult { Protocol = System.Security.Authentication.SslProtocols.Tls12 };
        using var deadline = new CancellationTokenSource();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var probe = typeof(MailTlsAnalysis).GetMethod("ProbeProtocolSupport", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        var run = (Task)probe.Invoke(analysis, new object[] { MailProtocol.Smtp, new MailTransportEndpoint("mail.example.test", 25), result, deadline.Token })!;
        try {
            await started.Task.WaitWithCancellation(guard.Token);
            deadline.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            Assert.True(result.SupportsTls12);
            Assert.False(result.ProtocolSupportComplete);
            Assert.False(result.SupportsTls10);
            Assert.False(result.SupportsTls11);
        } finally { pending.TrySetResult(Array.Empty<IPAddress>()); }
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConnectBudgetStopsAwaitingAnUncooperativeCustomResolver(bool startTls) {
        var release = new TaskCompletionSource<IReadOnlyList<IPAddress>>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try {
            if (startTls) {
                var analysis = new STARTTLSAnalysis { ConnectTimeout = TimeSpan.FromMilliseconds(30), OutboundAddressResolver = (_, _) => release.Task };
                await analysis.AnalyzeServer("mail.example.test", 25, new InternalLogger(), guard.Token);
                Assert.Contains(analysis.Assessments, item => item.Code == "MAILTLS.Service.NotOffered");
            } else {
                var analysis = new MailTlsAnalysis { ConnectTimeout = TimeSpan.FromMilliseconds(30), OutboundAddressResolver = (_, _) => release.Task };
                await analysis.AnalyzeServer(MailProtocol.Imap, "mail.example.test", 143, new InternalLogger(), guard.Token);
                Assert.Equal(CertificateFailureKind.Timeout, Assert.Single(analysis.ServerResults).Value.FailureKind);
            }
            Assert.False(release.Task.IsCompleted);
        } finally { release.TrySetResult(Array.Empty<IPAddress>()); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InfiniteProtocolBudgetStillBoundsTheConnection(bool startTls) {
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> resolver = async (_, token) => {
            await Task.Delay(Timeout.Infinite, token);
            return Array.Empty<IPAddress>();
        };
        if (startTls) {
            var analysis = new STARTTLSAnalysis { Timeout = Timeout.InfiniteTimeSpan, ConnectTimeout = TimeSpan.FromMilliseconds(30), OutboundAddressResolver = resolver };
            await analysis.AnalyzeServer("mail.example.test", 25, new InternalLogger(), guard.Token);
            Assert.Contains(analysis.Assessments, item => item.Code == "MAILTLS.Service.NotOffered");
        } else {
            var analysis = new MailTlsAnalysis { Timeout = Timeout.InfiniteTimeSpan, ConnectTimeout = TimeSpan.FromMilliseconds(30), OutboundAddressResolver = resolver };
            await analysis.AnalyzeServer(MailProtocol.Imap, "mail.example.test", 143, new InternalLogger(), guard.Token);
            Assert.Equal(CertificateFailureKind.Timeout, Assert.Single(analysis.ServerResults).Value.FailureKind);
        }
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, false)]
    [InlineData(false, false, true)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    public async Task CancellationStopsMaterializingTheHostSequence(bool startTls, bool explicitTargets, bool alreadyCanceled) {
        using var canceled = new CancellationTokenSource();
        if (alreadyCanceled) { canceled.Cancel(); }
        int enumerated = 0;
        IEnumerable<string> Hosts() {
            enumerated++;
            canceled.Cancel();
            yield return "mail.example.test";
            enumerated++;
            throw new InvalidOperationException("Enumeration continued after cancellation.");
        }
        Task Run() => startTls
            ? new STARTTLSAnalysis().AnalyzeServers(Hosts(), new[] { 25 }, new InternalLogger(), canceled.Token)
            : explicitTargets
                ? new MailTlsAnalysis().AnalyzeServers(MailProtocol.Imap, Hosts().Select(host => new MailTransportEndpoint(host, 143)), new InternalLogger(), canceled.Token)
                : new MailTlsAnalysis().AnalyzeServers(MailProtocol.Imap, Hosts(), 143, new InternalLogger(), canceled.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(Run);
        Assert.Equal(alreadyCanceled ? 0 : 1, enumerated);
    }

    [Fact]
    public async Task CancellationDuringHiddenStartTlsHandshakePropagates() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var canceled = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Task.Run(async () => {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream);
            using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
            await writer.WriteLineAsync("454 TLS required");
            Assert.StartsWith("EHLO", await reader.ReadLineAsync());
            await writer.WriteLineAsync("250 OK");
            Assert.Equal("STARTTLS", await reader.ReadLineAsync());
            await writer.WriteLineAsync("220 Begin TLS");
            var handshake = new byte[1];
            Assert.Equal(1, await stream.ReadAsync(handshake, 0, 1, canceled.Token));
            canceled.Cancel();
            await release.Task;
        });
        try {
            var analysis = new STARTTLSAnalysis();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeServer(
                new MailTransportEndpoint("mail.example.test", port) { ConnectAddress = IPAddress.Loopback }, new InternalLogger(), canceled.Token));
            Assert.Empty(analysis.ServerDetails);
        } finally {
            release.TrySetResult(true);
            listener.Stop();
            await server;
        }
    }

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
        Assert.Equal(CertificateFailureKind.Timeout, Assert.Single(analysis.ServerResults).Value.FailureKind);
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
