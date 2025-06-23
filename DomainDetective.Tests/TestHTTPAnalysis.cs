using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestHTTPAnalysis {
        [Fact]
        public async Task DetectStatusCodeAndHsts() {
            var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis();
                await analysis.AnalyzeUrl(prefix, true, new InternalLogger());
                Assert.True(analysis.IsReachable);
                Assert.Equal(200, analysis.StatusCode);
                Assert.True(analysis.ResponseTime > TimeSpan.Zero);
                Assert.True(analysis.HstsPresent);
                Assert.Equal(analysis.ProtocolVersion >= new Version(2, 0), analysis.Http2Supported);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task NotFoundStatusSetsIsReachableFalse() {
            var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
            });

            try {
                var analysis = new HttpAnalysis();
                await analysis.AnalyzeUrl(prefix, false, new InternalLogger());
                Assert.False(analysis.IsReachable);
                Assert.Equal(404, analysis.StatusCode);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task UnreachableHostSetsIsReachableFalse() {
            var analysis = new HttpAnalysis();
            var url = $"http://localhost:{GetFreePort()}/";
            await analysis.AnalyzeUrl(url, false, new InternalLogger());
            Assert.False(analysis.IsReachable);
            Assert.False(string.IsNullOrEmpty(analysis.FailureReason));
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