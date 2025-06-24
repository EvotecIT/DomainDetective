using DomainDetective;
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
                var healthCheck = new DomainHealthCheck { MtaStsPolicyUrlOverride = prefix + ".well-known/mta-sts.txt" };
                await healthCheck.Verify("example.com", [HealthCheckType.MTASTS]);

                Assert.True(healthCheck.MTASTSAnalysis.PolicyPresent);
                Assert.True(healthCheck.MTASTSAnalysis.PolicyValid);
                Assert.Equal("enforce", healthCheck.MTASTSAnalysis.Mode);
                Assert.Single(healthCheck.MTASTSAnalysis.Mx);
                Assert.Equal("mail.example.com", healthCheck.MTASTSAnalysis.Mx[0]);
            } finally {
                listener.Stop();
                await serverTask;
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