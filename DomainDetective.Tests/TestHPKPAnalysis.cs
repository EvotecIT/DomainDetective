using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestHPKPAnalysis {
        [Fact]
        public async Task DetectsHeaderAndValidPins() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=1000";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                Assert.True(analysis.HeaderPresent);
                Assert.True(analysis.PinsValid);
                Assert.Equal(2, analysis.Pins.Count);
                Assert.Contains(pin1, analysis.Pins);
                Assert.Contains(pin2, analysis.Pins);
                Assert.Equal(1000, analysis.MaxAge);
                Assert.False(analysis.IncludesSubDomains);
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task InvalidPinFormat() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var header = "pin-sha256=\"invalidbase64\"; max-age=1000";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                ctx.Response.Close();
            });
            try {
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                Assert.True(analysis.HeaderPresent);
                Assert.False(analysis.PinsValid);
                Assert.Equal(1000, analysis.MaxAge);
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task DetectsIncludeSubDomains() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=10; includeSubDomains";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                ctx.Response.Close();
            });
            try {
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                Assert.True(analysis.HeaderPresent);
                Assert.True(analysis.PinsValid);
                Assert.True(analysis.IncludesSubDomains);
                Assert.Equal(10, analysis.MaxAge);
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task SelfSignedAllowsSinglePin() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin = Convert.ToBase64String(Enumerable.Repeat((byte)6, 32).ToArray());
            var header = $"pin-sha256=\"{pin}\"; max-age=100";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                ctx.Response.Close();
            });
            try {
                var analysis = new HPKPAnalysis { SelfSignedCertificate = true };
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                Assert.True(analysis.HeaderPresent);
                Assert.True(analysis.PinsValid);
                Assert.Single(analysis.Pins);
                Assert.Equal(pin, analysis.Pins.First());
                Assert.Equal(100, analysis.MaxAge);
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task WarnsOnHpKPHeader() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)7, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)8, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=200";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                ctx.Response.Close();
            });
            try {
                var logger = new InternalLogger();
                var warnings = new List<LogEventArgs>();
                logger.OnWarningMessage += (_, e) => warnings.Add(e);
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, logger);
                Assert.True(analysis.HeaderPresent);
                Assert.Contains(warnings, w => w.FullMessage.Contains("obsolete"));
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task HeaderMissing() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Close();
            });
            try {
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                Assert.False(analysis.HeaderPresent);
            } finally {
                listener.Stop();
                await task;
            }
        }

        [Fact]
        public async Task CachedHeaderReusedUntilExpiration() {
            HPKPAnalysis.ClearCache();
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)9, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)10, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=100";
            int hitCount = 0;
            var task = Task.Run(async () => {
                while (listener.IsListening) {
                    var ctx = await listener.GetContextAsync();
                    hitCount++;
                    ctx.Response.Headers.Add("Public-Key-Pins", header);
                    ctx.Response.Close();
                }
            });

            try {
                var analysis = new HPKPAnalysis { CacheDuration = TimeSpan.FromMilliseconds(500) };
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                await analysis.AnalyzeUrl(prefix, new InternalLogger());

                Assert.Equal(1, hitCount);

                await Task.Delay(600);
                await analysis.AnalyzeUrl(prefix, new InternalLogger());

                Assert.Equal(2, hitCount);
            } finally {
                listener.Stop();
                await Task.Delay(50);
            }
        }

        [Fact]
        public async Task CachedMissingHeaderReusedUntilExpiration() {
            HPKPAnalysis.ClearCache();
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            int hitCount = 0;
            var task = Task.Run(async () => {
                while (listener.IsListening) {
                    var ctx = await listener.GetContextAsync();
                    hitCount++;
                    ctx.Response.StatusCode = 200;
                    ctx.Response.Close();
                }
            });

            try {
                var analysis = new HPKPAnalysis { CacheDuration = TimeSpan.FromMilliseconds(500) };
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                await analysis.AnalyzeUrl(prefix, new InternalLogger());

                Assert.Equal(1, hitCount);

                await Task.Delay(600);
                await analysis.AnalyzeUrl(prefix, new InternalLogger());

                Assert.Equal(2, hitCount);
            } finally {
                listener.Stop();
                await Task.Delay(50);
            }
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }
    }}