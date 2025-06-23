using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestHPKPHealthCheck {
        [Fact]
        public async Task VerifyViaHealthCheck() {
            var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)3, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)4, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=500";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.TrimEnd('/').Replace("http://", string.Empty), [HealthCheckType.HPKP]);
                Assert.True(healthCheck.HPKPAnalysis.HeaderPresent);
                Assert.True(healthCheck.HPKPAnalysis.PinsValid);
                Assert.Equal(2, healthCheck.HPKPAnalysis.Pins.Count);
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
