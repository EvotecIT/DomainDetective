using System;
using System.Net;
using System.Threading.Tasks;
using Xunit.Sdk;

namespace DomainDetective.Tests {
    [Collection("HttpListener")]
    public class TestPlainHttpHealthCheck {
        [Fact]
        public async Task VerifyPlainHttpDetectsStatusWithoutHsts() {
            Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
            using var listener = new HttpListener();
            var port = GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            PortHelper.ReleasePort(port);
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
                await healthCheck.VerifyPlainHttp(domain!));
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

        [Fact]
        public async Task VerifyPlainHttpUsesExplicitPort() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.HttpAnalysis.Timeout = TimeSpan.FromMilliseconds(500);  
            await healthCheck.VerifyPlainHttp("example.com:8080");
            var visited = Assert.Single(healthCheck.HttpAnalysis.VisitedUrls);
            var visitedUri = new Uri(visited, UriKind.Absolute);
            Assert.Equal("http", visitedUri.Scheme);
            Assert.Equal("example.com", visitedUri.Host);
            Assert.Equal(8080, visitedUri.Port);
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }
    }
}
