using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestSecurityTXTAnalysis {
        [Fact]
        public async Task ValidSecurityTxtIsParsed() {
            using var listener = new HttpListener();
            var prefix = $"http://127.0.0.1:{GetFreePort()}/";
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

        [Fact]
        public async Task DuplicateTagsMakeRecordInvalid() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var expires = DateTime.UtcNow.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}\nExpires: {expires}";
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
                Assert.Contains("expires", healthCheck.SecurityTXTAnalysis.DuplicateTags);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task ExpiredDateMakesRecordInvalid() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var expires = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
              var serverTask = Task.Run(async () => {
                  try {
                      var ctx = await listener.GetContextAsync();
                      ctx.Response.StatusCode = 200;
                      ctx.Response.ContentType = "text/plain";
                      var buffer = Encoding.UTF8.GetBytes(content);
                      await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                      ctx.Response.Close();
                  } catch (ObjectDisposedException) {
                      // HttpListener was stopped before GetContextAsync completed
                  }
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

        [Fact]
        public async Task MalformedFileIsInvalid() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var content = "Contact: not-a-valid-contact";
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

        [Fact]
        public async Task CachedSecurityTxtReusedUntilExpiration() {
            SecurityTXTAnalysis.ClearCache();
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();

            var expires = DateTime.UtcNow.AddSeconds(2).ToString("yyyy-MM-ddTHH:mm:ssZ");
            var content = $"Contact: mailto:admin@example.com\nExpires: {expires}";
            int hitCount = 0;
            var serverTask = Task.Run(async () => {
                while (listener.IsListening) {
                    var ctx = await listener.GetContextAsync();
                    hitCount++;
                    ctx.Response.StatusCode = 200;
                    ctx.Response.ContentType = "text/plain";
                    var buffer = Encoding.UTF8.GetBytes(content);
                    await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                    ctx.Response.Close();
                }
            });

            try {
                var healthCheck = new DomainHealthCheck();
                var domain = prefix.Replace("http://", string.Empty).TrimEnd('/');
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });

                Assert.Equal(1, hitCount);

                await Task.Delay(2100);
                await healthCheck.Verify(domain, new[] { HealthCheckType.SECURITYTXT });

                Assert.Equal(2, hitCount);
            } finally {
                listener.Stop();
                await Task.Delay(50);
            }
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }
    }
}

