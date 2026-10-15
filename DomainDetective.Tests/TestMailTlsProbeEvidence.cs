using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public class TestMailTlsProbeEvidence {
    [EphemeralTlsFact]
    public async Task PrimarySessionGradeSurvivesAnAuxiliaryProbeDeadline() {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = Task.Run(async () => {
            for (int attempt = 0; attempt < 2; attempt++) {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, System.Text.Encoding.ASCII, false, 1024, true);
                using var writer = new StreamWriter(stream, System.Text.Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 localhost");
                Assert.StartsWith("EHLO ", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                await writer.WriteLineAsync("250 STARTTLS");
                Assert.Equal("STARTTLS", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                if (attempt == 1) { await release.Task; continue; }
                await writer.WriteLineAsync("220 Begin TLS");
                using var ssl = new SslStream(stream, true);
                await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false).WaitWithCancellation(guard.Token);
                using var secureReader = new StreamReader(ssl);
                Assert.Equal("QUIT", await secureReader.ReadLineAsync().WaitWithCancellation(guard.Token));
            }
        });
        try {
            var analysis = new MailTlsAnalysis { Timeout = TimeSpan.FromSeconds(2) };
            await analysis.AnalyzeServer(MailTlsAnalysis.MailProtocol.Smtp,
                new MailTransportEndpoint("localhost", port) { ConnectAddress = IPAddress.Loopback }, new InternalLogger(), guard.Token);
            var result = Assert.Single(analysis.ServerResults).Value;
            Assert.Equal(SslProtocols.Tls12, result.Protocol);
            Assert.NotNull(result.Certificate);
            Assert.NotEqual(GradeLevel.Unknown, result.GradeLevel);
            Assert.True(result.SupportsTls12);
            Assert.Equal(CertificateFailureKind.Timeout, result.FailureKind);
            Assert.False(result.ProtocolSupportComplete);
        } finally {
            release.TrySetResult(true);
            guard.Cancel();
            listener.Stop();
            try { await server; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
            catch (SocketException) when (guard.IsCancellationRequested) { }
        }
    }

    [Fact]
    public async Task LegacyPolicyDoesNotRequireSuccessfulModernVersionProbes() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () => {
            for (int attempt = 0; attempt < 3; attempt++) {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream, System.Text.Encoding.ASCII, false, 1024, true);
                using var writer = new StreamWriter(stream, System.Text.Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 localhost");
                Assert.StartsWith("EHLO ", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                if (attempt == 0) { await writer.WriteLineAsync("451 Try later"); continue; }
                await writer.WriteLineAsync("250 STARTTLS");
                Assert.Equal("STARTTLS", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                await writer.WriteLineAsync("220 Begin TLS");
                var firstByte = new byte[1];
                int count = await stream.ReadAsync(firstByte, 0, 1, guard.Token);
                if (count == 1 && firstByte[0] == 22) {
                    // Drain the ClientHello record so closing the socket cannot reset an unread request
                    // and hide the protocol-version rejection from the client.
                    var header = new byte[4];
                    await ReadFullyAsync(stream, header, guard.Token);
                    int length = (header[2] << 8) | header[3];
                    Assert.InRange(length, 1, 18432);
                    await ReadFullyAsync(stream, new byte[length], guard.Token);
                    var protocolVersionAlert = new byte[] { 21, 3, 3, 0, 2, 2, 70 };
                    await stream.WriteAsync(protocolVersionAlert, 0, protocolVersionAlert.Length, guard.Token);
                }
            }
        });
        try {
            var analysis = new MailTlsAnalysis();
            var result = new MailTlsAnalysis.TlsResult { Protocol = SslProtocols.Tls12, StartTlsAdvertised = true };
            var probe = typeof(MailTlsAnalysis).GetMethod("ProbeProtocolSupport", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
            await (Task)probe.Invoke(analysis, new object[] { MailTlsAnalysis.MailProtocol.Smtp,
                new MailTransportEndpoint("localhost", port) { ConnectAddress = IPAddress.Loopback }, result, guard.Token })!;
            Assert.False(result.ProtocolSupportComplete);
            Assert.False(result.SupportsTls10);
            Assert.False(result.SupportsTls11);
            using var health = new DomainHealthCheck();
            health.SmtpTlsAnalysis.ServerResults["localhost:25"] = result;
            var evaluated = DomainDetective.DesiredState.DesiredStateEvaluator.Evaluate("example.test", health,
                new DomainDetective.DesiredState.DesiredStateProfile { SmtpTls = new DomainDetective.DesiredState.DesiredStateMailTlsPolicy {
                    DisallowLegacyProtocols = true, RequireCertificateValid = false, RequireChainValid = false,
                    RequireHostnameMatch = false, DisallowExpiredCertificates = false
                } });
            Assert.True(evaluated.Conforms, string.Join("; ", evaluated.Assessments.Select(item => item.Code)));
            Assert.DoesNotContain(evaluated.Assessments, item => item.Code == "DesiredState.MailTls.ProtocolSupport.QueryFailed");
        } finally {
            guard.Cancel();
            listener.Stop();
            try { await server; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { }
            catch (SocketException) when (guard.IsCancellationRequested) { }
        }
    }

    private static async Task ReadFullyAsync(Stream stream, byte[] bytes, CancellationToken token) {
        int offset = 0;
        while (offset < bytes.Length) {
            int read = await stream.ReadAsync(bytes, offset, bytes.Length - offset, token);
            if (read == 0) { throw new EndOfStreamException("TLS record ended before its declared length."); }
            offset += read;
        }
    }
}
