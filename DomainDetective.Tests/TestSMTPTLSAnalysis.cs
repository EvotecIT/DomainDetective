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

        [Fact]
        public async Task ResultsDoNotAccumulateAcrossCalls() {
            using var cert = CreateSelfSigned();
            var listener1 = new TcpListener(IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((IPEndPoint)listener1.LocalEndpoint).Port;
            using var cts1 = new CancellationTokenSource();
            var serverTask1 = Task.Run(async () => {
                try {
                    while (!cts1.Token.IsCancellationRequested) {
                        var acceptTask = listener1.AcceptTcpClientAsync();
                        var completed = await Task.WhenAny(acceptTask, Task.Delay(Timeout.Infinite, cts1.Token));
                        if (completed != acceptTask) {
                            try { await acceptTask; } catch { }
                            break;
                        }

                        var client = await acceptTask;
                        _ = Task.Run(async () => {
                            using var tcp = client;
                            using var ssl = new SslStream(tcp.GetStream());
                            await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                        }, cts1.Token);
                    }
                } catch { }
            }, cts1.Token);

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
            var serverTask2 = Task.Run(async () => {
                try {
                    while (!cts2.Token.IsCancellationRequested) {
                        var acceptTask = listener2.AcceptTcpClientAsync();
                        var completed = await Task.WhenAny(acceptTask, Task.Delay(Timeout.Infinite, cts2.Token));
                        if (completed != acceptTask) {
                            try { await acceptTask; } catch { }
                            break;
                        }

                        var client = await acceptTask;
                        _ = Task.Run(async () => {
                            using var tcp = client;
                            using var ssl = new SslStream(tcp.GetStream());
                            await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                        }, cts2.Token);
                    }
                } catch { }
            }, cts2.Token);

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

        private static X509Certificate2 CreateSelfSigned() {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }
}
