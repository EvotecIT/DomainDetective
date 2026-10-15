using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;

namespace DomainDetective.Tests;

public class TestMailTlsRemoteEvidence {
    [Theory]
    [InlineData(70, true)]
    [InlineData(40, false)]
    public async Task OnlyRemoteVersionRejectionCompletesANegativeProtocolProbe(byte alert, bool complete) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () => {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            await UpgradeAsync(stream, guard.Token);
            await RejectHelloAsync(stream, alert, guard.Token);
        });
        try {
            var result = new MailTlsAnalysis.TlsResult {
                Protocol = (SslProtocols)12288, SupportsTls13 = true, SupportsTls10 = true, SupportsTls11 = true
            };
            var probe = typeof(MailTlsAnalysis).GetMethod("ProbeProtocolSupport", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            await (Task)probe.Invoke(new MailTlsAnalysis(), new object[] { MailTlsAnalysis.MailProtocol.Smtp,
                new MailTransportEndpoint("localhost", ((IPEndPoint)listener.LocalEndpoint).Port) { ConnectAddress = IPAddress.Loopback }, result, guard.Token })!;
            Assert.False(result.SupportsTls12);
            Assert.Equal(complete, result.ProtocolSupportComplete);
            await server;
        } finally {
            guard.Cancel();
            listener.Stop();
        }
    }

    [Fact]
    public async Task AuxiliaryTimeoutPreservesThePrimaryHandshakeFailure() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Task.Run(async () => {
            using (var first = await listener.AcceptTcpClientAsync()) {
                using var stream = first.GetStream();
                await UpgradeAsync(stream, guard.Token);
                await RejectHelloAsync(stream, 40, guard.Token);
            }
            using var second = await listener.AcceptTcpClientAsync();
            using var transport = second.GetStream();
            await UpgradeAsync(transport, guard.Token);
            await release.Task.WaitWithCancellation(guard.Token);
        });
        try {
            var analysis = new MailTlsAnalysis { Timeout = TimeSpan.FromSeconds(2) };
            await analysis.AnalyzeServer(MailTlsAnalysis.MailProtocol.Smtp,
                new MailTransportEndpoint("localhost", ((IPEndPoint)listener.LocalEndpoint).Port) { ConnectAddress = IPAddress.Loopback }, new InternalLogger(), guard.Token);
            var result = Assert.Single(analysis.ServerResults).Value;
            Assert.NotEqual(CertificateFailureKind.None, result.FailureKind);
            Assert.NotEqual(CertificateFailureKind.Timeout, result.FailureKind);
            Assert.NotNull(result.FailureReason);
            Assert.False(result.ProtocolSupportComplete);
        } finally {
            release.TrySetResult(true);
            guard.Cancel();
            listener.Stop();
            try { await server; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
            catch (SocketException) when (guard.IsCancellationRequested) { }
        }
    }

    [Theory]
    [InlineData(MailTlsAnalysis.MailProtocol.Smtp, 465, true)]
    [InlineData(MailTlsAnalysis.MailProtocol.Imap, 993, true)]
    [InlineData(MailTlsAnalysis.MailProtocol.Pop3, 995, true)]
    [InlineData(MailTlsAnalysis.MailProtocol.Smtp, 2525, false)]
    [InlineData(MailTlsAnalysis.MailProtocol.Imap, 1143, false)]
    [InlineData(MailTlsAnalysis.MailProtocol.Pop3, 1110, false)]
    public void StandardImplicitTlsPortsSkipStartTls(MailTlsAnalysis.MailProtocol protocol, int port, bool direct) {
        var selector = typeof(MailTlsAnalysis).GetMethod("UsesDirectTls", System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)!;
        Assert.Equal(direct, selector.Invoke(null, new object[] { protocol, port }));
    }

    private static async Task UpgradeAsync(Stream stream, CancellationToken token) {
        using var reader = new StreamReader(stream, System.Text.Encoding.ASCII, false, 1024, true);
        using var writer = new StreamWriter(stream, System.Text.Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
        await writer.WriteLineAsync("220 localhost");
        Assert.StartsWith("EHLO ", await reader.ReadLineAsync().WaitWithCancellation(token));
        await writer.WriteLineAsync("250 STARTTLS");
        Assert.Equal("STARTTLS", await reader.ReadLineAsync().WaitWithCancellation(token));
        await writer.WriteLineAsync("220 Begin TLS");
    }

    private static async Task RejectHelloAsync(Stream stream, byte alert, CancellationToken token) {
        async Task ReadFully(byte[] bytes) {
            int offset = 0;
            while (offset < bytes.Length) {
                int read = await stream.ReadAsync(bytes, offset, bytes.Length - offset, token);
                if (read == 0) { throw new EndOfStreamException(); }
                offset += read;
            }
        }
        var header = new byte[5];
        await ReadFully(header);
        Assert.Equal(22, header[0]);
        int length = (header[3] << 8) | header[4];
        Assert.InRange(length, 1, 18432);
        await ReadFully(new byte[length]);
        var rejection = new byte[] { 21, 3, 3, 0, 2, 2, alert };
        await stream.WriteAsync(rejection, 0, rejection.Length, token);
        await stream.FlushAsync(token);
    }
}
