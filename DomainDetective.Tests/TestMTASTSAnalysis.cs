using DomainDetective;
using DnsClientX;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestMTASTSAnalysis {
        [Fact]
        public void ParseValidPolicy() {
            var policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.True(analysis.PolicyValid);
            Assert.True(analysis.ValidVersion);
            Assert.True(analysis.ValidMode);
            Assert.True(analysis.ValidMaxAge);
            Assert.True(analysis.HasMx);
            Assert.Equal("enforce", analysis.Mode);
            Assert.Equal(86400, analysis.MaxAge);
            Assert.Single(analysis.Mx);
            Assert.Equal("mail.example.com", analysis.Mx[0]);
            Assert.True(analysis.EnforcesMtaSts);
        }

        [Fact]
        public void MissingFieldsInvalidatePolicy() {
            var policy = "version: STSv1\nmode: enforce";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.PolicyValid);
            Assert.False(analysis.HasMx);
            Assert.False(analysis.ValidMaxAge);
            Assert.False(analysis.EnforcesMtaSts);
        }

        [Fact]
        public void PolicyNotEnforcedWhenModeTesting() {
            var policy = "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.True(analysis.PolicyValid);
            Assert.Equal("testing", analysis.Mode);
            Assert.False(analysis.EnforcesMtaSts);
        }

        [Fact]
        public void MissingVersionInvalidatesPolicy() {
            var policy = "mode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.PolicyValid);
            Assert.False(analysis.VersionPresent);
            Assert.False(analysis.ValidVersion);
        }

        [Fact]
        public void DuplicateFieldsInvalidatePolicy() {
            var policy = "version: STSv1\nmode: enforce\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.True(analysis.HasDuplicateFields);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task FetchPolicyFromServer() {
            using var listener = new HttpListener();
            var port = GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            const string policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                if (ctx.Request.Url.AbsolutePath == "/.well-known/mta-sts.txt") {
                    var data = Encoding.UTF8.GetBytes(policy);
                    ctx.Response.StatusCode = 200;
                    await ctx.Response.OutputStream.WriteAsync(data, 0, data.Length);
                } else {
                    ctx.Response.StatusCode = 404;
                }
                ctx.Response.Close();
            });

            try {
                var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1; id=abc", Type = DnsRecordType.TXT } };
                var analysis = new MTASTSAnalysis {
                    PolicyUrlOverride = prefix + ".well-known/mta-sts.txt",
                    QueryDnsOverride = (_, _) => Task.FromResult(answers),
                    DnsConfiguration = new DnsConfiguration()
                };

                await analysis.AnalyzePolicy("example.com", new InternalLogger());

                Assert.True(analysis.PolicyPresent);
                Assert.True(analysis.PolicyValid);
                Assert.True(analysis.DnsRecordPresent);
                Assert.True(analysis.DnsRecordValid);
                Assert.Equal("abc", analysis.PolicyId);
                Assert.Equal("enforce", analysis.Mode);
                Assert.Single(analysis.Mx);
                Assert.Equal("mail.example.com", analysis.Mx[0]);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ParseDnsRecord() {
            const string policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1; id=123" , Type = DnsRecordType.TXT } };
            using var listener = new HttpListener();
            var port = GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                var data = Encoding.UTF8.GetBytes(policy);
                ctx.Response.StatusCode = 200;
                await ctx.Response.OutputStream.WriteAsync(data, 0, data.Length);
                ctx.Response.Close();
            });

            try {
                var analysis = new MTASTSAnalysis {
                    PolicyUrlOverride = prefix + ".well-known/mta-sts.txt",
                    QueryDnsOverride = (_, _) => Task.FromResult(answers),
                    DnsConfiguration = new DnsConfiguration()
                };
                await analysis.AnalyzePolicy("example.com", new InternalLogger());

                Assert.True(analysis.DnsRecordPresent);
                Assert.True(analysis.DnsRecordValid);
                Assert.Equal("123", analysis.PolicyId);
                Assert.True(analysis.PolicyValid);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task MissingDnsRecordFails() {
            var analysis = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());

            Assert.False(analysis.DnsRecordPresent);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task MalformedDnsRecordFails() {
            var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1", Type = DnsRecordType.TXT } };
            var analysis = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(answers),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());

            Assert.True(analysis.DnsRecordPresent);
            Assert.False(analysis.DnsRecordValid);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public void InvalidVersionInvalidatesPolicy() {
            var policy = "version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.ValidVersion);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public void InvalidModeInvalidatesPolicy() {
            var policy = "version: STSv1\nmode: invalid\nmx: mail.example.com\nmax_age: 86400";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.ValidMode);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public void InvalidMaxAgeInvalidatesPolicy() {
            var policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: -1";
            var analysis = new MTASTSAnalysis();
            analysis.AnalyzePolicyText(policy);

            Assert.False(analysis.ValidMaxAge);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task InvalidDnsRecordVersionFails() {
            var answers = new[] { new DnsAnswer { DataRaw = "v=STSx; id=abc", Type = DnsRecordType.TXT } };
            var analysis = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(answers),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());

            Assert.True(analysis.DnsRecordPresent);
            Assert.False(analysis.DnsRecordValid);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task InvalidDnsRecordMissingVersionFails() {
            var answers = new[] { new DnsAnswer { DataRaw = "id=abc", Type = DnsRecordType.TXT } };
            var analysis = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(answers),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());

            Assert.True(analysis.DnsRecordPresent);
            Assert.False(analysis.DnsRecordValid);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task InvalidDnsRecordMissingIdFails() {
            var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1", Type = DnsRecordType.TXT } };
            var analysis = new MTASTSAnalysis {
                QueryDnsOverride = (_, _) => Task.FromResult(answers),
                DnsConfiguration = new DnsConfiguration()
            };
            await analysis.AnalyzePolicy("example.com", new InternalLogger());

            Assert.True(analysis.DnsRecordPresent);
            Assert.False(analysis.DnsRecordValid);
            Assert.False(analysis.PolicyValid);
        }

        [Fact]
        public async Task CachedPolicyReusedUntilExpiration() {
            MTASTSAnalysis.ClearCache();
            using var listener = new HttpListener();
            var port = GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            const string policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400";
            int hitCount = 0;
            var serverTask = Task.Run(async () => {
                while (listener.IsListening) {
                    var ctx = await listener.GetContextAsync();
                    if (ctx.Request.Url.AbsolutePath == "/.well-known/mta-sts.txt") {
                        hitCount++;
                        var data = Encoding.UTF8.GetBytes(policy);
                        ctx.Response.StatusCode = 200;
                        await ctx.Response.OutputStream.WriteAsync(data, 0, data.Length);
                    } else {
                        ctx.Response.StatusCode = 404;
                    }
                    ctx.Response.Close();
                }
            });

            try {
                var answers = new[] { new DnsAnswer { DataRaw = "v=STSv1; id=abc", Type = DnsRecordType.TXT } };
                var analysis = new MTASTSAnalysis {
                    PolicyUrlOverride = prefix + ".well-known/mta-sts.txt",
                    QueryDnsOverride = (_, _) => Task.FromResult(answers),
                    DnsConfiguration = new DnsConfiguration(),
                    CacheDuration = TimeSpan.FromMilliseconds(500)
                };

                await analysis.AnalyzePolicy("example.com", new InternalLogger());
                await analysis.AnalyzePolicy("example.com", new InternalLogger());

                Assert.Equal(1, hitCount);

                await Task.Delay(600);
                await analysis.AnalyzePolicy("example.com", new InternalLogger());

                Assert.Equal(2, hitCount);
            } finally {
                listener.Stop();
                await Task.Delay(50);
            }
        }

        private static int GetFreePort() {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var p = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return p;
        }
    }
}