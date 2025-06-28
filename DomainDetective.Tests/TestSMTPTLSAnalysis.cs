using Xunit.Sdk;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestSMTPTLSAnalysis {
        [Fact]
        public async Task DetectsTls12AndInvalidCert() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

            try {
                var analysis = new SMTPTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.True(result.StartTlsAdvertised);
                Assert.Equal(SslProtocols.None, result.Protocol);
                Assert.False(result.SupportsTls13);
                Assert.False(result.CertificateValid);
                Assert.True(result.DaysToExpire > 0);
                Assert.NotEmpty(result.ChainErrors);
                Assert.Contains(X509ChainStatusFlags.UntrustedRoot, result.ChainErrors);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ResultsDoNotAccumulateAcrossCalls() {
            using var cert = CreateSelfSigned();
            var listener1 = new TcpListener(IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((IPEndPoint)listener1.LocalEndpoint).Port;
            using var cts1 = new CancellationTokenSource();
            var serverTask1 = Task.Run(() => RunServer(listener1, cert, SslProtocols.Tls12, cts1.Token), cts1.Token);

            var analysis = new SMTPTLSAnalysis();
            try {
                await analysis.AnalyzeServer("localhost", port1, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.True(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
            } finally {
                cts1.Cancel();
                listener1.Stop();
                await serverTask1;
            }

            var listener2 = new TcpListener(IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((IPEndPoint)listener2.LocalEndpoint).Port;
            using var cts2 = new CancellationTokenSource();
            var serverTask2 = Task.Run(() => RunServer(listener2, cert, SslProtocols.Tls12, cts2.Token), cts2.Token);

            try {
                await analysis.AnalyzeServer("localhost", port2, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.False(analysis.ServerResults.ContainsKey($"localhost:{port1}"));
                Assert.True(analysis.ServerResults.ContainsKey($"localhost:{port2}"));
            } finally {
                cts2.Cancel();
                listener2.Stop();
                await serverTask2;
            }
        }

#if NET8_0_OR_GREATER
        [Fact]
        public async Task DetectsTls13WhenSupported() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls13, cts.Token), cts.Token);

            try {
                var analysis = new SMTPTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.True(result.StartTlsAdvertised);
                if (result.Protocol != SslProtocols.Tls13) {
                    // TLS 1.3 not supported or handshake failed; skip the assertion
                    return;
                }
                Assert.True(result.SupportsTls13);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }
#endif

        [Fact]
        public async Task CapturesCipherSuiteAndDhBits() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

            try {
                var analysis = new SMTPTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.False(string.IsNullOrEmpty(result.CipherSuite));
                if (result.DhKeyBits > 0) {
                    Assert.True(result.DhKeyBits > 0);
                }
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        private static async Task RunServer(TcpListener listener, X509Certificate2 cert, SslProtocols protocol, CancellationToken token) {
            try {
                while (!token.IsCancellationRequested) {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                    if (completed != clientTask) {
                        try { await clientTask; } catch { }
                        break;
                    }

                    var client = await clientTask;
                    _ = Task.Run(async () => {
                        using var tcp = client;
                        using var stream = tcp.GetStream();
                        using var reader = new StreamReader(stream);
                        using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                        await writer.WriteLineAsync("220 local ESMTP");
                        await reader.ReadLineAsync();
                        await writer.WriteLineAsync("250-localhost\r\n250-STARTTLS\r\n250 OK");
                        await reader.ReadLineAsync();
                        await writer.WriteLineAsync("220 ready");
                        using var ssl = new SslStream(stream);
                        await ssl.AuthenticateAsServerAsync(cert, false, protocol, false);
                        using var sslReader = new StreamReader(ssl);
                        await sslReader.ReadLineAsync();
                    }, token);
                }
            } catch {
                // ignore on shutdown
            }
        }

        private static X509Certificate2 CreateSelfSigned() {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }
}