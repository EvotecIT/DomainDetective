using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestSecurityTXTAnalysis {
        [Fact]
        public async Task ValidSecurityTxtIsParsed() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "text/plain";
                var buffer = Encoding.UTF8.GetBytes(content);
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
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
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Expires: {expires}";
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "text/plain";
                var buffer = Encoding.UTF8.GetBytes(content);
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
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

        private static int GetFreePort() {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}
