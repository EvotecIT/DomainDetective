using DnsClientX;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using RichardSzalay.MockHttp;

namespace DomainDetective.Tests {
    public class TestBimiAnalysis {
        [Fact]
        public async Task ParseBimiRecord() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() =>
                RunServer(
                    listener,
                    cert,
                    _ => ("image/svg+xml", Encoding.UTF8.GetBytes("<svg width='64' height='64' viewBox='0 0 64 64'></svg>")),
                    cts.Token),
                cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.BimiRecordExists);
                Assert.True(analysis.StartsCorrectly);
                Assert.Equal($"{prefix}logo.svg", analysis.Location);
                Assert.True(analysis.LocationUsesHttps);
                Assert.True(analysis.SvgFetched);
                Assert.True(analysis.SvgValid);
                Assert.True(analysis.DimensionsValid);
                Assert.True(analysis.ViewBoxValid);
                Assert.True(analysis.SvgSizeValid);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParseBimiRecordHttp() {
            var record = "v=BIMI1; l=http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, logger);

            Assert.True(analysis.BimiRecordExists);
            Assert.True(analysis.StartsCorrectly);
            Assert.Equal("http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", analysis.Location);
            Assert.False(analysis.LocationUsesHttps);
            Assert.True(analysis.InvalidLocation);
            Assert.False(analysis.SvgFetched);
            Assert.Contains(warnings, w => w.FullMessage.Contains("Invalid BIMI indicator location"));
        }

        [Fact]
        public async Task InvalidSchemeMarksLocationInvalid() {
            var record = "v=BIMI1; l=ftp://example.com/logo.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

            Assert.True(analysis.InvalidLocation);
            Assert.False(analysis.SvgFetched);
        }

        [Fact]
        public async Task UnreachableIndicatorSetsFailureReason() {
            var port = GetFreePort();
            var record = $"v=BIMI1; l=https://localhost:{port}/logo.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT }
            };
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

            Assert.False(string.IsNullOrEmpty(analysis.FailureReason));
            Assert.False(analysis.SvgFetched);
        }

        [Fact]
        public async Task InvalidSvgFailsValidation() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, _ => ("image/svg+xml", Encoding.UTF8.GetBytes("<html></html>")), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> {
                    new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT }
                };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.SvgFetched);
                Assert.False(analysis.SvgValid);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task MalformedSvgFailsValidation() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, _ => ("image/svg+xml", Encoding.UTF8.GetBytes("<!DOCTYPE svg PUBLIC '-//W3C//DTD SVG 1.1//EN' 'http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd'><svg></svg>")), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> {
                    new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT }
                };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.SvgFetched);
                Assert.False(analysis.SvgValid);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task SvgMissingViewBoxProducesWarning() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, _ => ("image/svg+xml", Encoding.UTF8.GetBytes("<svg width='64' height='64'></svg>")), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var logger = new InternalLogger();
                var warnings = new List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, logger);

                Assert.True(analysis.SvgFetched);
                Assert.False(analysis.ViewBoxValid);
                Assert.Contains(warnings, w => w.FullMessage.Contains("viewBox"));
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task SvgLargerThan32KbInvalid() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var big = "<svg width='64' height='64' viewBox='0 0 64 64'>" + new string('A', 33000) + "</svg>";
            var serverTask = Task.Run(() => RunServer(listener, cert, _ => ("image/svg+xml", Encoding.UTF8.GetBytes(big)), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var logger = new InternalLogger();
                var warnings = new List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, logger);

                Assert.True(analysis.SvgFetched);
                Assert.False(analysis.SvgSizeValid);
                Assert.Contains(warnings, w => w.FullMessage.Contains("exceeds"));
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ValidVmcCertificate() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, path => path.EndsWith(".svg")
                ? ("image/svg+xml", Encoding.UTF8.GetBytes("<svg></svg>"))
                : ("application/pkix-cert", cert.Export(X509ContentType.Cert)), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg; a={prefix}vmc.cer";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.SvgValid);
                Assert.True(analysis.ValidVmc);
                Assert.False(analysis.VmcSignedByKnownRoot);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task VmcWithLogoMetadata() {
            using var cert = CreateVmc();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, path => path.EndsWith(".svg")
                ? ("image/svg+xml", Encoding.UTF8.GetBytes("<svg></svg>"))
                : ("application/pkix-cert", cert.Export(X509ContentType.Cert)), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg; a={prefix}vmc.cer";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.VmcContainsLogo);
                Assert.True(analysis.ValidVmc);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task VmcFromFileServedOverHttp() {
            var vmcBytes = File.ReadAllBytes(Path.Combine("Data", "vmc.pem"));
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cts = new CancellationTokenSource();
            var serverTask = Task.Run(() => RunServer(listener, cert, path =>
                path.EndsWith(".svg")
                    ? ("image/svg+xml", Encoding.UTF8.GetBytes("<svg></svg>"))
                    : ("application/pkix-cert", vmcBytes), cts.Token), cts.Token);
            var prefix = $"https://localhost:{port}/";

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg; a={prefix}vmc.cer";
                var answers = new List<DnsAnswer> { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.ValidVmc);
                Assert.True(analysis.VmcContainsLogo);
            } finally {
                cts.Cancel();
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task RedirectIsFollowedWhenDownloadingSvg() {
            var mock = new MockHttpMessageHandler();
            mock.When("https://example.com/logo.svg").Respond(_ => {
                var resp = new HttpResponseMessage(HttpStatusCode.Moved);
                resp.Headers.Location = new Uri("https://example.com/logo2.svg");
                return resp;
            });
            mock.When("https://example.com/logo2.svg")
                .Respond("image/svg+xml", "<svg width='64' height='64' viewBox='0 0 64 64'></svg>");

            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = "v=BIMI1; l=https://example.com/logo.svg",
                    Type = DnsRecordType.TXT
                }
            };

            var analysis = new BimiAnalysis {
                HttpHandlerFactory = () => new RedirectMockHandler(mock)
            };
            await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

            Assert.True(analysis.SvgFetched);
            Assert.True(analysis.SvgValid);
        }

        private sealed class RedirectMockHandler : DelegatingHandler {
            public RedirectMockHandler(HttpMessageHandler inner)
                : base(inner) { }

            protected override async Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken) {
                var response = await base.SendAsync(request, cancellationToken);
                if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400
                    && response.Headers.Location != null) {
                    var follow = new HttpRequestMessage(request.Method, response.Headers.Location);
                    foreach (var header in request.Headers) {
                        follow.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }
                    response = await base.SendAsync(follow, cancellationToken);
                }
                return response;
            }
        }

        private static X509Certificate2 CreateSelfSigned() {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=example", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }

        private static X509Certificate2 CreateVmc() {
            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var req = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=example", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            var data = System.Text.Encoding.ASCII.GetBytes("image/svg+xml");
            req.CertificateExtensions.Add(new X509Extension("1.3.6.1.5.5.7.1.12", data, false));
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }

        private static int GetFreePort() {
            var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            var port = ((IPEndPoint)socket.LocalEndpoint).Port;
            socket.Stop();
            return port;
        }

        private static async Task RunServer(TcpListener listener, X509Certificate2 cert, Func<string, (string contentType, byte[] data)> response, CancellationToken token) {
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
                        await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                        using var reader = new StreamReader(ssl);
                        using var writer = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                        var requestLine = await reader.ReadLineAsync();
                        if (requestLine == null) { return; }
                        string line;
                        do { line = await reader.ReadLineAsync(); } while (!string.IsNullOrEmpty(line));
                        var path = requestLine.Split(' ')[1];
                        var resp = response(path);
                        await writer.WriteLineAsync("HTTP/1.1 200 OK");
                        await writer.WriteLineAsync($"Content-Type: {resp.contentType}");
                        await writer.WriteLineAsync($"Content-Length: {resp.data.Length}");
                        await writer.WriteLineAsync();
                        await ssl.WriteAsync(resp.data, 0, resp.data.Length, token);
                    }, token);
                }
            } catch {
                // ignore on shutdown
            }
        }
    }
}