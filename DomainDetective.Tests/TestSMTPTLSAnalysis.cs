using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Threading;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSMTPTLSAnalysis {
        [Fact]
        public async Task DetectsTls12AndInvalidCert() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(async () => {
                try {
                    while (!cts.Token.IsCancellationRequested) {
                        var acceptTask = listener.AcceptTcpClientAsync();
                        var completed = await Task.WhenAny(acceptTask, Task.Delay(Timeout.Infinite, cts.Token));
                        if (completed != acceptTask) {
                            try { await acceptTask; } catch { /* ignore */ }
                            break;
                        }

                        var client = await acceptTask;
                        _ = Task.Run(async () => {
                            using var tcp = client;
                            using var ssl = new SslStream(tcp.GetStream());
                            await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                        }, cts.Token);
                    }
                } catch (OperationCanceledException) {
                    // expected on shutdown
                } catch (ObjectDisposedException) {
                    // listener stopped
                } catch (SocketException) {
                    // listener stopped
                }
            }, cts.Token);

            try {
                var analysis = new SMTPTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.Contains(SslProtocols.Tls12, result.SupportedProtocols);
                Assert.False(result.CertificateValid);
                Assert.True(result.DaysToExpire > 0);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
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
