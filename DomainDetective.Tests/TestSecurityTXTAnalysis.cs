using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Xunit.Sdk;

namespace DomainDetective.Tests {
    [Collection("HttpListener")]
    public class TestSecurityTXTAnalysis {
        [Fact]
        public async Task ValidSecurityTxtIsParsed() {
            using var listener = StartListener(out var prefix);
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SECURITYTXT });
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordPresent);
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordValid);
                Assert.True(healthCheck.SecurityTXTAnalysis.FallbackUsed);
                Assert.Contains("admin@example.com", healthCheck.SecurityTXTAnalysis.ContactEmail);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task MissingContactMakesRecordInvalid() {
            using var listener = StartListener(out var prefix);
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Expires: {expires}";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SECURITYTXT });
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordPresent);
                Assert.False(healthCheck.SecurityTXTAnalysis.RecordValid);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DuplicateTagsMakeRecordInvalid() {
            using var listener = StartListener(out var prefix);
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}\nExpires: {expires}";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SECURITYTXT });
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordPresent);
                Assert.False(healthCheck.SecurityTXTAnalysis.RecordValid);
                Assert.Contains("expires", healthCheck.SecurityTXTAnalysis.DuplicateTags);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ExpiredDateMakesRecordInvalid() {
            using var listener = StartListener(out var prefix);
            var expires = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SECURITYTXT });
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordPresent);
                Assert.False(healthCheck.SecurityTXTAnalysis.RecordValid);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task MalformedFileIsInvalid() {
            using var listener = StartListener(out var prefix);
            var content = "Contact: not-a-valid-contact";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'), new[] { HealthCheckType.SECURITYTXT });
                Assert.True(healthCheck.SecurityTXTAnalysis.RecordPresent);
                Assert.False(healthCheck.SecurityTXTAnalysis.RecordValid);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task CachedSecurityTxtReusedUntilExpiration() {
            SecurityTXTAnalysis.ClearCache();
            using var listener = StartListener(out var prefix);

            var expires = DateTime.UtcNow.AddSeconds(2).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
            int hitCount = 0;
            var serverTask = Task.Run(async () => {
                while (listener.IsListening) {
                    try {
                        var ctx = await listener.GetContextAsync();
                        hitCount++;
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "text/plain";
                        var buffer = Encoding.UTF8.GetBytes(content);
                        await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                        ctx.Response.Close();
                    } catch (ObjectDisposedException) {
                        break;
                    } catch (HttpListenerException) {
                        break;
                    }
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                var domain = prefix.Replace("http://", string.Empty).TrimEnd('/');
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });

                Assert.Equal(1, hitCount);

                await Task.Delay(2100);
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });

                Assert.Equal(2, hitCount);
            } finally {
                listener.Stop();
                await Task.Delay(50);
            }
        }

        [Fact]
        public async Task NoContentTypeHeaderDoesNotThrow() {
            using var listener = StartListener(out var prefix);
            var content = "Contact: mailto:admin@example.com";
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                var ex = await Record.ExceptionAsync(() =>
                    healthCheck.Verify(prefix.Replace("http://", string.Empty).TrimEnd('/'),
                        new[] { HealthCheckType.SECURITYTXT }));
                Assert.Null(ex);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task SignedSecurityTxtWarnsWhenPgpVerificationIsUnavailable() {
            using var listener = StartListener(out var prefix);
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content =
                $"""
                -----BEGIN PGP SIGNED MESSAGE-----
                Hash: SHA256

                Contact: mailto:admin@example.com
                Expires: {expires}
                -----BEGIN PGP SIGNATURE-----
                placeholder
                -----END PGP SIGNATURE-----
                """;
            var serverTask = Task.Run(async () => {
                try {
                    var ctx = await listener.GetContextAsync();
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                } catch (ObjectDisposedException) {
                    // listener stopped before context was retrieved
                } catch (HttpListenerException) {
                    // listener stopped before context was retrieved
                }
            });

            try {
                var warnings = new List<LogEventArgs>();
                var logger = new InternalLogger();
                logger.OnWarningMessage += (_, args) => warnings.Add(args);
                var analysis = new SecurityTXTAnalysis();

                await analysis.AnalyzeSecurityTxtRecord(
                    prefix.Replace("http://", string.Empty).TrimEnd('/'),
                    logger,
                    pgpPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----");

                Assert.True(analysis.PGPSigned);
                Assert.True(analysis.RecordValid);
                Assert.Contains("admin@example.com", analysis.ContactEmail);
                Assert.Contains(
                    warnings,
                    warning => warning.Code == SecurityTxtCodes.SignatureVerifyFailed &&
                               (warning.FullMessage.Contains("no verifier is registered", StringComparison.OrdinalIgnoreCase) ||
                                warning.FullMessage.Contains("PGP signature verification failed", StringComparison.OrdinalIgnoreCase)));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }

        private static HttpListener StartListener(out string prefix) {
            Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
            while (true) {
                var port = GetFreePort();
                prefix = $"http://127.0.0.1:{port}/";
                var l = new HttpListener();
                l.Prefixes.Add(prefix);
                try {
                    l.Start();
                    PortHelper.ReleasePort(port);
                    return l;
                } catch (HttpListenerException) {
                    l.Close();
                    PortHelper.ReleasePort(port);
                }
            }
        }
    }
}
