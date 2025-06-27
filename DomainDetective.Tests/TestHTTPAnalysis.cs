using System;
using System.Net;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestHTTPAnalysis {
        [Fact]
        public async Task DetectStatusCodeAndHsts() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
                ctx.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                ctx.Response.Headers.Add("Expect-CT", "max-age=86400, enforce");
                ctx.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
                ctx.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                ctx.Response.Headers.Add("X-Frame-Options", "DENY");
                ctx.Response.Headers.Add("Referrer-Policy", "no-referrer");
                ctx.Response.Headers.Add("Permissions-Policy", "geolocation=()" );
                ctx.Response.Headers.Add("X-Permitted-Cross-Domain-Policies", "none");
                ctx.Response.Headers.Add("Cross-Origin-Opener-Policy", "same-origin");
                ctx.Response.Headers.Add("Cross-Origin-Embedder-Policy", "require-corp");
                ctx.Response.Headers.Add("Cross-Origin-Resource-Policy", "same-origin");
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, true, new InternalLogger(), collectHeaders: true, captureBody: true);
                Assert.True(analysis.IsReachable);
                Assert.Equal(200, analysis.StatusCode);
                Assert.True(analysis.ResponseTime > TimeSpan.Zero);
                Assert.True(analysis.HstsPresent);
                Assert.True(analysis.XssProtectionPresent);
                Assert.True(analysis.ExpectCtPresent);
                Assert.Equal(analysis.ProtocolVersion >= new Version(2, 0), analysis.Http2Supported);
                Assert.Equal("default-src 'self'", analysis.SecurityHeaders["Content-Security-Policy"].Value);
                Assert.Equal("1; mode=block", analysis.SecurityHeaders["X-XSS-Protection"].Value);
                Assert.Equal("max-age=86400, enforce", analysis.SecurityHeaders["Expect-CT"].Value);
                Assert.Equal(86400, analysis.ExpectCtMaxAge);
                Assert.Null(analysis.ExpectCtReportUri);
                Assert.Equal("nosniff", analysis.SecurityHeaders["X-Content-Type-Options"].Value);
                Assert.Equal("DENY", analysis.SecurityHeaders["X-Frame-Options"].Value);
                Assert.Equal("no-referrer", analysis.SecurityHeaders["Referrer-Policy"].Value);
                Assert.Equal("geolocation=()", analysis.SecurityHeaders["Permissions-Policy"].Value);
                Assert.Equal("max-age=31536000", analysis.SecurityHeaders["Strict-Transport-Security"].Value);
                Assert.Equal("none", analysis.SecurityHeaders["X-Permitted-Cross-Domain-Policies"].Value);
                Assert.Equal("same-origin", analysis.SecurityHeaders["Cross-Origin-Opener-Policy"].Value);
                Assert.Equal("require-corp", analysis.SecurityHeaders["Cross-Origin-Embedder-Policy"].Value);
                Assert.Equal("same-origin", analysis.SecurityHeaders["Cross-Origin-Resource-Policy"].Value);
                Assert.Equal(31536000, analysis.HstsMaxAge);
                Assert.False(analysis.HstsIncludesSubDomains);
                Assert.False(analysis.HstsTooShort);
                Assert.Equal("ok", analysis.Body);
                Assert.Single(analysis.MissingSecurityHeaders, "Public-Key-Pins");
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task NotFoundStatusSetsIsReachableFalse() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger());
                Assert.False(analysis.IsReachable);
                Assert.Equal(404, analysis.StatusCode);
                Assert.Null(analysis.ProtocolVersion);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var analysis = new HttpAnalysis {
                RequestVersion = HttpVersion.Version11
            };
            var url = $"http://localhost:{GetFreePort()}/";
            await analysis.AnalyzeUrl(url, false, new InternalLogger());
            Assert.False(analysis.IsReachable);
            Assert.False(string.IsNullOrEmpty(analysis.FailureReason));
            Assert.Null(analysis.ProtocolVersion);
        }

        [Fact]
        public async Task DoesNotCollectHeadersWhenDisabled() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
                ctx.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                ctx.Response.Headers.Add("Expect-CT", "max-age=86400, enforce");
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger());
                Assert.True(analysis.SecurityHeaders.Count == 0);
                Assert.True(analysis.MissingSecurityHeaders.Count == 0);
                Assert.False(analysis.XssProtectionPresent);
                Assert.False(analysis.ExpectCtPresent);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task FollowsRedirectsWhenUsingHttp3() {
            using var listener1 = new HttpListener();
            var prefix1 = $"http://localhost:{GetFreePort()}/";
            listener1.Prefixes.Add(prefix1);
            listener1.Start();

            using var listener2 = new HttpListener();
            var prefix2 = $"http://localhost:{GetFreePort()}/";
            listener2.Prefixes.Add(prefix2);
            listener2.Start();

            var task1 = Task.Run(async () => {
                var ctx = await listener1.GetContextAsync();
                ctx.Response.StatusCode = 302;
                ctx.Response.RedirectLocation = prefix2;
                ctx.Response.Close();
            });

            var task2 = Task.Run(async () => {
                var ctx = await listener2.GetContextAsync();
                ctx.Response.StatusCode = 200;
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix1, false, new InternalLogger());
                Assert.True(analysis.IsReachable);
                Assert.Equal(200, analysis.StatusCode);
            } finally {
                listener1.Stop();
                listener2.Stop();
                await Task.WhenAll(task1, task2);
            }
        }

        [Fact]
        public async Task ThrowsWhenMaxRedirectsExceeded() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            var serverTask = Task.Run(async () => {
                while (true) {
                    HttpListenerContext ctx;
                    try {
                        ctx = await listener.GetContextAsync();
                    } catch (HttpListenerException) {
                        break;
                    } catch (ObjectDisposedException) {
                        break;
                    }
                    ctx.Response.StatusCode = 302;
                    ctx.Response.RedirectLocation = prefix;
                    ctx.Response.Close();
                }
            });

            try {
                var analysis = new HttpAnalysis {
                    MaxRedirects = 2,
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger());
                Assert.False(analysis.IsReachable);
                Assert.Equal(302, analysis.StatusCode);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task TimeoutSetsFailureReason() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var tcs = new TaskCompletionSource<object?>();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                await tcs.Task;
                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    Timeout = TimeSpan.FromMilliseconds(200),
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger());
                Assert.False(analysis.IsReachable);
                Assert.False(string.IsNullOrEmpty(analysis.FailureReason));
            } finally {
                tcs.TrySetResult(null);
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsHstsTooShortAndIncludesSubDomains() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=1000; includeSubDomains");
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, true, new InternalLogger(), collectHeaders: true);
                Assert.True(analysis.HstsPresent);
                Assert.Equal(1000, analysis.HstsMaxAge);
                Assert.True(analysis.HstsIncludesSubDomains);
                Assert.True(analysis.HstsTooShort);
                Assert.Contains("Content-Security-Policy", analysis.MissingSecurityHeaders);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsUnsafeContentSecurityPolicyDirectives() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'");
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger(), collectHeaders: true);
                Assert.True(analysis.CspUnsafeDirectives);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParsesExpectCtReportUri() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Expect-CT", "max-age=10, report-uri=\"https://example.com/report\"");
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger(), collectHeaders: true);
                Assert.True(analysis.ExpectCtPresent);
                Assert.Equal(10, analysis.ExpectCtMaxAge);
                Assert.Equal("https://example.com/report", analysis.ExpectCtReportUri);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task DetectsPublicKeyPinsHeaderWithWarning() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Public-Key-Pins", "pin-sha256=\"abc\"; max-age=1000");
                ctx.Response.Close();
            });

            try {
                var logger = new InternalLogger();
                var warnings = new List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new HttpAnalysis {
                    RequestVersion = HttpVersion.Version11
                };
                await analysis.AnalyzeUrl(prefix, false, logger, collectHeaders: true);
                Assert.True(analysis.PublicKeyPinsPresent);
                Assert.Contains(warnings, w => w.FullMessage.Contains("deprecated"));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static int GetFreePort() {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}