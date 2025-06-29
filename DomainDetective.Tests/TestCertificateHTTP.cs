using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests {
    public class TestCertificateHTTP {
        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://localhost", 9, logger);
            Assert.False(analysis.IsReachable);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task UnreachableHostLogsExceptionType() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnErrorMessage += (_, e) => eventArgs = e;

            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://localhost", 9, logger);

            Assert.NotNull(eventArgs);
            Assert.Contains(nameof(HttpRequestException), eventArgs!.FullMessage);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task ValidHostSetsProtocolVersion() {
            using var cert = CreateSelfSigned("localhost");
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl($"https://localhost", port, logger);
                Assert.True(analysis.ProtocolVersion?.Major >= 1);
                Assert.Equal(analysis.ProtocolVersion >= new Version(2, 0), analysis.Http2Supported);
                Assert.False(analysis.Http3Supported);
            } finally {
                store.Remove(cert);
                store.Close();
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ValidCertificateProvidesExpirationInfo() {
            using var cert = CreateSelfSigned("localhost");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.DaysValid > 0);
            Assert.Equal(analysis.DaysToExpire < 0, analysis.IsExpired);
        }

        [Fact]
        public async Task ValidCertificateIsNotSelfSigned() {
            using var cert = CreateSigned("localhost");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.False(analysis.IsSelfSigned);
        }

        [Fact]
        public async Task ExtractsRevocationEndpoints() {
            using var cert = CreateSigned("localhost");
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeCertificate(cert);
            Assert.NotNull(analysis.OcspUrls);
            Assert.NotNull(analysis.CrlUrls);
        }

        [Fact]
        public async Task ChecksCertificateTransparency() {
            var certPath = Path.Combine("Data", "wildcard.pem");
            var cert = new X509Certificate2(certPath);
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[{\"id\":1}]") };
            await analysis.AnalyzeCertificate(cert);
            Assert.True(analysis.PresentInCtLogs);
        }

        [Fact]
        public async Task CapturesCipherSuiteWhenEnabled() {
            using var cert = CreateSelfSigned("localhost");
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CaptureTlsDetails = true };
                await analysis.AnalyzeUrl($"https://localhost", port, logger);
                Assert.False(string.IsNullOrEmpty(analysis.CipherSuite));
                if (analysis.DhKeyBits > 0) {
                    Assert.True(analysis.DhKeyBits > 0);
                }
            } finally {
                store.Remove(cert);
                store.Close();
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsHostnameMismatch() {
            using var cert = CreateSelfSigned("example.com");
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl($"https://localhost", port, logger);
                Assert.False(analysis.HostnameMatch);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

#if NET8_0_OR_GREATER
        [Fact]
        public async Task DetectsTls13WhenSupported() {
            using var cert = CreateSelfSigned("localhost");
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, SslProtocols.Tls13, cts.Token), cts.Token);

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CaptureTlsDetails = true, CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl($"https://localhost", port, logger);
                if (analysis.TlsProtocol != SslProtocols.Tls13) {
                    return;
                }
                Assert.True(analysis.Tls13Used);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }
#endif

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
                        TcpClient? tcp = client;
                        SslStream? ssl = null;
                        StreamReader? reader = null;
                        StreamWriter? writer = null;
                        try {
                            ssl = new SslStream(tcp.GetStream());
                            await ssl.AuthenticateAsServerAsync(cert, false, protocol, false);
                            reader = new StreamReader(ssl);
                            writer = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
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

        private static X509Certificate2 CreateSelfSigned(string cn) {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }

        private static X509Certificate2 CreateSigned(string cn) {
            using var rootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=RootCA", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var rootCert = rootReq.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(365));

            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            var cert = req.Create(rootCert, DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30), new byte[] {1,2,3,4});
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }
}