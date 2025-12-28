using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestExecutionCache {
        [Fact]
        public async Task GetMxRecordsAsync_CachesResults() {
            var healthCheck = new DomainHealthCheck(DnsEndpoint.System, new InternalLogger(false));
            var first = healthCheck.GetMxRecordsAsyncForTest("example.com", CancellationToken.None);
            var second = healthCheck.GetMxRecordsAsyncForTest("example.com", CancellationToken.None);

            Assert.Same(first, second);

            try {
                await first;
            } catch {
                // Ignore DNS/network failures; we only validate caching behavior.
            }
        }

        [Fact]
        public async Task GetMxRecordsAsync_InvalidatesOnDomainChange() {
            var healthCheck = new DomainHealthCheck(DnsEndpoint.System, new InternalLogger(false));
            var first = healthCheck.GetMxRecordsAsyncForTest("example.com", CancellationToken.None);
            var second = healthCheck.GetMxRecordsAsyncForTest("example.org", CancellationToken.None);
            var third = healthCheck.GetMxRecordsAsyncForTest("example.com", CancellationToken.None);

            Assert.NotSame(first, second);
            Assert.NotSame(first, third);

            try {
                await Task.WhenAll(first, second, third);
            } catch {
                // Ignore DNS/network failures; we only validate caching behavior.
            }
        }
    }
}
