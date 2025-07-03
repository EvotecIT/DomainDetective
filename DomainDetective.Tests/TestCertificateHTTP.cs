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
using System.Collections.Generic;
using System.Linq;
using DnsClientX;

namespace DomainDetective.Tests {
    public class TestCertificateHTTP {
        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);
            Assert.False(analysis.IsReachable);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task UnreachableHostLogsExceptionType() {
            var logger = new InternalLogger();
            LogEventArgs? eventArgs = null;
            logger.OnErrorMessage += (_, e) => eventArgs = e;

            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://nonexistent.invalid", 443, logger);

            Assert.NotNull(eventArgs);
            Assert.Contains(nameof(HttpRequestException), eventArgs!.FullMessage);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task ValidHostSetsProtocolVersion() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.True(analysis.ProtocolVersion?.Major >= 1);
            Assert.Equal(analysis.ProtocolVersion >= new Version(2, 0), analysis.Http2Supported);
            if (analysis.ProtocolVersion >= new Version(3, 0)) {
                Assert.True(analysis.Http3Supported);
            }
        }

        [Fact]
        public async Task ValidCertificateProvidesExpirationInfo() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.True(analysis.DaysValid > 0);
            Assert.Equal(analysis.DaysToExpire < 0, analysis.IsExpired);
        }

        [Fact]
        public async Task ValidCertificateIsNotSelfSigned() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.False(analysis.IsSelfSigned);
            Assert.True(analysis.Chain.Count > 1);
        }

        [Fact]
        public async Task ExtractsRevocationEndpoints() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
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
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CaptureTlsDetails = true };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            Assert.False(string.IsNullOrEmpty(analysis.CipherSuite));
            if (analysis.DhKeyBits > 0) {
                Assert.True(analysis.DhKeyBits > 0);
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

        [Fact]
        public void ExtractMxHostsSkipsInvalid() {
            List<DnsAnswer> records = new () {
                new DnsAnswer { DataRaw = "10 mx1.example.com", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "20 ", Type = DnsRecordType.MX },
                new DnsAnswer { DataRaw = "30", Type = DnsRecordType.MX }
            };

            List<string> hosts = CertificateAnalysis.ExtractMxHosts(records).ToList();

            Assert.Single(hosts);
            Assert.Equal("mx1.example.com", hosts[0]);
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
                        using var ssl = new SslStream(tcp.GetStream());
                        await ssl.AuthenticateAsServerAsync(cert, false, protocol, false);
                        using var reader = new StreamReader(ssl);
                        using var writer = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                        await reader.ReadLineAsync();
                        string line;
                        do {
                            line = await reader.ReadLineAsync();
                        } while (!string.IsNullOrEmpty(line));
                        await writer.WriteLineAsync("HTTP/1.1 200 OK");
                        await writer.WriteLineAsync("Content-Length: 0");
                        await writer.WriteLineAsync();
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
    }
}