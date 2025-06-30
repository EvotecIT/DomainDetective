using System;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestPlainHttpHealthCheck {
        [Fact]
        public async Task VerifyPlainHttpDetectsStatusWithoutHsts() {
            using var listener = new HttpListener();
            var port = GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
                ctx.Response.Close();
            });

            try {
                var healthCheck = new DomainHealthCheck();
                await healthCheck.VerifyPlainHttp($"localhost:{port}");

                Assert.True(healthCheck.HttpAnalysis.IsReachable);
                Assert.Equal(200, healthCheck.HttpAnalysis.StatusCode);
                Assert.False(healthCheck.HttpAnalysis.HstsPresent);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public async Task VerifyPlainHttpThrowsIfDomainNullOrWhitespace(string? domain) {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await healthCheck.VerifyPlainHttp(domain));
        }

        [Theory]
        [InlineData("invalid host")]
        [InlineData("foo/bar")]
        [InlineData("http://example.com")]
        [InlineData("localhost:70000")]
        public async Task VerifyPlainHttpThrowsIfDomainInvalid(string domain) {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifyPlainHttp(domain));
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
