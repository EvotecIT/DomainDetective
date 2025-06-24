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

        private static int GetFreePort() {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}