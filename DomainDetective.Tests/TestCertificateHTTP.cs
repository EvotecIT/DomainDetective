using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using Xunit.Sdk;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using DnsClientX;
using DomainDetective.Tests.Fixtures;

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
            Assert.Contains("Exception reaching https://nonexistent.invalid", eventArgs!.FullMessage, StringComparison.OrdinalIgnoreCase);
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public void BuildFailureReason_AppendsSocketAndTimeoutMarkers() {
            var socket = new SocketException((int)SocketError.TimedOut);
            var timeout = new TimeoutException("The operation timed out.", socket);
            var http = new HttpRequestException("Unable to connect to the remote server.", timeout);

            string? reason = CertificateAnalysis.BuildFailureReason(http);

            Assert.NotNull(reason);
            Assert.Contains("SocketError:TimedOut", reason, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("FailureKind:Timeout", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void BuildFailureReason_AppendsCancelledMarkerForCancellation() {
            var cancelled = new TaskCanceledException("Request was cancelled.");
            var http = new HttpRequestException("Request aborted.", cancelled);

            string? reason = CertificateAnalysis.BuildFailureReason(http);

            Assert.NotNull(reason);
            Assert.Contains("FailureKind:Cancelled", reason, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("FailureKind:Timeout", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void BuildFailureReason_PrefersTimeoutMarkerOverInnerCancelledMarker() {
            var cancelled = new TaskCanceledException("A task was canceled.");
            var timeout = new TimeoutException("The request timed out.", cancelled);
            var http = new HttpRequestException("Request aborted.", timeout);

            string? reason = CertificateAnalysis.BuildFailureReason(http);

            Assert.NotNull(reason);
            Assert.Contains("The request timed out.", reason, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("FailureKind:Timeout", reason, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("FailureKind:Cancelled", reason, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("A task was canceled.", reason, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void NormalizeProbeException_ConvertsProbeTimeoutCancellationToTimeoutException() {
            using var timeoutCts = new CancellationTokenSource();
            timeoutCts.Cancel();
            var cancelled = new TaskCanceledException("Request was cancelled.");

            Exception normalized = CertificateAnalysis.NormalizeProbeException(
                cancelled,
                CancellationToken.None,
                timeoutCts);

            Assert.IsType<TimeoutException>(normalized);
            Assert.IsType<TaskCanceledException>(normalized.InnerException);
        }

        [Fact]
        public void NormalizeProbeException_PreservesCallerCancellation() {
            using var callerCts = new CancellationTokenSource();
            callerCts.Cancel();
            var cancelled = new OperationCanceledException(callerCts.Token);

            Exception normalized = CertificateAnalysis.NormalizeProbeException(
                cancelled,
                callerCts.Token);

            Assert.Same(cancelled, normalized);
        }

        [Fact]
        public void TlsProbe_NormalizeProbeException_ConvertsProbeTimeoutCancellationToTimeoutException() {
            using var timeoutCts = new CancellationTokenSource();
            timeoutCts.Cancel();
            var cancelled = new TaskCanceledException("TLS probe timed out.");

            Exception normalized = TlsProbe.NormalizeProbeException(
                cancelled,
                CancellationToken.None,
                timeoutCts);

            Assert.IsType<TimeoutException>(normalized);
            Assert.IsType<TaskCanceledException>(normalized.InnerException);
        }

        [Fact]
        public void TlsProbe_NormalizeProbeException_PreservesCallerCancellation() {
            using var callerCts = new CancellationTokenSource();
            callerCts.Cancel();
            var cancelled = new OperationCanceledException(callerCts.Token);

            Exception normalized = TlsProbe.NormalizeProbeException(
                cancelled,
                callerCts.Token);

            Assert.Same(cancelled, normalized);
        }

        [Fact]
        public async Task TlsProbe_CapturesRemoteEndpoint() {
            using var cert = CreateSelfSigned("localhost");
            var server = new TcpListenerFixture((l, t) => Task.Run(() => RunTlsOnlyServer(l, cert, SslProtocols.Tls12, t), t));
            await server.InitializeAsync();

            try {
                using var result = await TlsProbe.ProbeAsync(IPAddress.Loopback, "localhost", server.Port, TimeSpan.FromSeconds(5), CancellationToken.None);

                Assert.Equal(IPAddress.Loopback, result.RemoteAddress);
                Assert.Equal(server.Port, result.RemotePort);
                Assert.NotNull(result.Certificate);
            } finally {
                await server.DisposeAsync();
            }
        }

        [Fact]
        public void TlsProbe_DefaultResultHasNullEndpointFields() {
            using var result = new TlsProbe.Result();

            Assert.Null(result.RemoteAddress);
            Assert.Null(result.RemotePort);
        }

        [Fact]
        public async Task TlsProbe_ThrowsOnConnectionFailure() {
            var port = PortHelper.GetFreePort();

            await Assert.ThrowsAnyAsync<Exception>(() =>
                TlsProbe.ProbeAsync(IPAddress.Loopback, "localhost", port, TimeSpan.FromMilliseconds(250), CancellationToken.None));
        }

        [Fact]
        public void BuildFailureReason_AppendsTlsHandshakeMarkerForAuthenticationFailure() {
            var handshake = new AuthenticationException("TLS handshake failed.");

            string? reason = CertificateAnalysis.BuildFailureReason(handshake);

            Assert.NotNull(reason);
            Assert.Contains("FailureKind:TlsHandshake", reason, StringComparison.OrdinalIgnoreCase);
        }

#if NET8_0_OR_GREATER
        [Fact]
        public void BuildFailureReason_AppendsHttpRequestErrorMarker() {
            var http = new HttpRequestException(
                HttpRequestError.NameResolutionError,
                "Name resolution failed.",
                null,
                null);

            string? reason = CertificateAnalysis.BuildFailureReason(http);

            Assert.NotNull(reason);
            Assert.Contains("HttpRequestError:NameResolutionError", reason, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("FailureKind:NameResolution", reason, StringComparison.OrdinalIgnoreCase);
        }
#endif

        [Fact]
        public void BuildFailureLogMessage_UsesCompactSummaryForConnectivityFailures() {
            var timeout = new TimeoutException("The operation timed out.");
            var http = new HttpRequestException("Unable to connect to the remote server.", timeout);

            string message = CertificateAnalysis.BuildFailureLogMessage(http);

            Assert.Equal(CertificateAnalysis.BuildFailureReason(http), message);
            Assert.DoesNotContain(Environment.NewLine + "   at ", message, StringComparison.Ordinal);
        }

        [Fact]
        public void BuildFailureLogMessage_PreservesDetailedUnexpectedExceptions() {
            var exception = new InvalidOperationException("Unexpected parser state.");

            string message = CertificateAnalysis.BuildFailureLogMessage(exception);

            Assert.Equal(exception.ToString(), message);
        }

        [Fact]
        public async Task ValidHostSetsProtocolVersion() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            if (!analysis.IsReachable) {
                return;
            }
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
            if (!analysis.IsReachable) {
                return;
            }
            Assert.True(analysis.DaysValid > 0);
            Assert.Equal(analysis.DaysToExpire < 0, analysis.IsExpired);
        }

        [Fact]
        public async Task ValidCertificateIsNotSelfSigned() {
            var logger = new InternalLogger();
            var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
            await analysis.AnalyzeUrl("https://www.google.com", 443, logger);
            if (!analysis.IsReachable) {
                // Avoid false negatives when the endpoint is unreachable in CI.
                return;
            }
            Assert.False(analysis.IsSelfSigned);
#if NET8_0_OR_GREATER
            Assert.True(analysis.Chain.Count > 1);
#else
            // .NET Framework chain building can return only the leaf on some machines.
            Assert.NotEmpty(analysis.Chain);
#endif
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
            if (!analysis.IsReachable) {
                return;
            }
            // Some platforms do not expose cipher suite details; accept empty.
            Assert.NotNull(analysis.CipherSuite);
        }

        [Fact]
        public async Task DetectsHostnameMismatch() {
            using var cert = CreateSelfSigned("example.com");
            var server = new TcpListenerFixture((l, t) => Task.Run(() => RunServer(l, cert, SslProtocols.Tls12, t), t));
            await server.InitializeAsync();

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl($"https://localhost", server.Port, logger);
                Assert.NotNull(analysis.Certificate);
                Assert.False(analysis.HostnameMatch);
                Assert.False(analysis.IsValid);
            } finally {
                await server.DisposeAsync();
            }
        }

        [Fact]
        public async Task ErrorHttpStatusPreservesCertificateButKeepsReachabilityFalse() {
            using var cert = CreateSelfSigned("localhost");
            var server = new TcpListenerFixture((l, t) => Task.Run(() => RunServer(l, cert, SslProtocols.Tls12, t, "HTTP/1.1 500 Internal Server Error"), t));
            await server.InitializeAsync();

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl("https://localhost", server.Port, logger);

                Assert.NotNull(analysis.Certificate);
                Assert.False(analysis.IsReachable);
                Assert.NotNull(analysis.ProtocolVersion);
            } finally {
                await server.DisposeAsync();
            }
        }

        [Fact]
        public async Task RedirectKeepsFirstObservedCertificate() {
            using var originCert = CreateSelfSigned("origin.invalid");
            using var redirectedCert = CreateSelfSigned("redirect.invalid");
            var redirectedServer = new TcpListenerFixture((l, t) => Task.Run(() => RunServer(l, redirectedCert, SslProtocols.Tls12, t), t));
            await redirectedServer.InitializeAsync();
            string redirectLocation = $"https://127.0.0.1:{redirectedServer.Port}/";
            var originServer = new TcpListenerFixture((l, t) => Task.Run(() => RunServer(
                l,
                originCert,
                SslProtocols.Tls12,
                t,
                "HTTP/1.1 302 Found",
                new[] { "Location: " + redirectLocation }), t));
            await originServer.InitializeAsync();

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl("https://localhost", originServer.Port, logger);

                Assert.NotNull(analysis.Certificate);
                Assert.Contains("CN=origin.invalid", analysis.Certificate!.Subject, StringComparison.OrdinalIgnoreCase);
            } finally {
                await originServer.DisposeAsync();
                await redirectedServer.DisposeAsync();
            }
        }

#if NET8_0_OR_GREATER
        [Fact]
        public async Task DetectsTls13WhenSupported() {
            using var cert = CreateSelfSigned("localhost");
            var server = new TcpListenerFixture((l, t) => Task.Run(() => RunServer(l, cert, SslProtocols.Tls13, t), t));
            await server.InitializeAsync();

            try {
                var logger = new InternalLogger();
                var analysis = new CertificateAnalysis { CaptureTlsDetails = true, CtLogQueryOverride = _ => Task.FromResult("[]") };
                await analysis.AnalyzeUrl($"https://localhost", server.Port, logger);
                if (analysis.TlsProtocol != SslProtocols.Tls13) {
                    return;
                }
                Assert.True(analysis.Tls13Used);
            } finally {
                await server.DisposeAsync();
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

        private static async Task RunServer(
            TcpListener listener,
            X509Certificate2 cert,
            SslProtocols protocol,
            CancellationToken token,
            string statusLine = "HTTP/1.1 200 OK",
            IReadOnlyList<string>? headers = null) {
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
                          string? line;
                          do {
                              line = await reader.ReadLineAsync();
                          } while (!string.IsNullOrEmpty(line));
                        await writer.WriteLineAsync(statusLine);
                        if (headers != null) {
                            foreach (string header in headers) {
                                await writer.WriteLineAsync(header);
                            }
                        }
                        await writer.WriteLineAsync("Content-Length: 0");
                        await writer.WriteLineAsync();
                    }, token);
                }
            } catch {
                // ignore on shutdown
            }
        }

        private static async Task RunTlsOnlyServer(
            TcpListener listener,
            X509Certificate2 cert,
            SslProtocols protocol,
            CancellationToken token) {
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
