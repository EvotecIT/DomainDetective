using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDuplicateHealthChecks {
        [Fact]
        public async Task DuplicatesExecuteOnce() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var pin = Convert.ToBase64String(Enumerable.Repeat((byte)5, 32).ToArray());
            var header = $"pin-sha256=\"{pin}\"; pin-sha256=\"{pin}\"; max-age=123";
            var count = 0;
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
                    count++;
                    ctx.Response.Headers.Add("Public-Key-Pins", header);
                    var buffer = Encoding.UTF8.GetBytes("ok");
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.Verify(prefix.TrimEnd('/').Replace("http://", string.Empty), new[] { HealthCheckType.HPKP, HealthCheckType.HPKP });
                Assert.True(healthCheck.HPKPAnalysis.HeaderPresent);
                Assert.Equal(1, count);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static int GetFreePort() {
            var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            var port = ((IPEndPoint)socket.LocalEndpoint).Port;
            socket.Stop();
            return port;
        }
    }
}
