using Xunit;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCertificateMonitor {
        [Fact]
        public async Task ProducesSummaryCounts() {
            using var cert = CreateSelfSigned();
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.Root, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
            store.Add(cert);
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new System.Threading.CancellationTokenSource();
            var serverTask = System.Threading.Tasks.Task.Run(() => RunServer(listener, cert, cts.Token), cts.Token);

            try {
                var monitor = new CertificateMonitor();
                await monitor.Analyze(new[] { $"https://localhost", "https://localhost" }, port);
                Assert.Equal(2, monitor.Results.Count);
                Assert.True(monitor.ValidCount >= 1);
            } finally {
                store.Remove(cert);
                store.Close();
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public void TimerStopsAfterDispose() {
            var monitor = new CertificateMonitor();
            monitor.Start(Array.Empty<string>(), TimeSpan.FromMilliseconds(10));
            Assert.True(monitor.IsRunning);
            monitor.Dispose();
            Assert.False(monitor.IsRunning);
        }

        private static async Task RunServer(System.Net.Sockets.TcpListener listener, System.Security.Cryptography.X509Certificates.X509Certificate2 cert, System.Threading.CancellationToken token) {
            try {
                while (!token.IsCancellationRequested) {
                    var clientTask = listener.AcceptTcpClientAsync();
                    var completed = await System.Threading.Tasks.Task.WhenAny(clientTask, System.Threading.Tasks.Task.Delay(System.Threading.Timeout.Infinite, token));
                    if (completed != clientTask) {
                        try { await clientTask; } catch { }
                        break;
                    }

                    var client = await clientTask;
                    _ = System.Threading.Tasks.Task.Run(async () => {
                        System.Net.Sockets.TcpClient? tcp = client;
                        System.Net.Security.SslStream? ssl = null;
                        System.IO.StreamReader? reader = null;
                        System.IO.StreamWriter? writer = null;
                        try {
                            ssl = new System.Net.Security.SslStream(tcp.GetStream());
                            await ssl.AuthenticateAsServerAsync(cert, false, System.Security.Authentication.SslProtocols.Tls12, false);
                            reader = new System.IO.StreamReader(ssl);
                            writer = new System.IO.StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                            await reader.ReadLineAsync();
                            string line;
                            do {
                                line = await reader.ReadLineAsync();
                            } while (!string.IsNullOrEmpty(line));
                            await writer.WriteLineAsync("HTTP/1.1 200 OK");
                            await writer.WriteLineAsync("Content-Length: 0");
                            await writer.WriteLineAsync();
                        } finally {
                            writer?.Dispose();
                            reader?.Dispose();
                            ssl?.Dispose();
                            tcp?.Dispose();
                        }
                    }, token);
                }
            } catch {
                // ignore on shutdown
            }
        }

        private static System.Security.Cryptography.X509Certificates.X509Certificate2 CreateSelfSigned() {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=localhost", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(System.DateTimeOffset.Now.AddDays(-1), System.DateTimeOffset.Now.AddDays(30));
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx));
        }
    }
}
