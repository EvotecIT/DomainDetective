using System.Net;
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

        [Fact]
        public async Task VerifySmtpTls_CacheIncludesAddressFamilyAndResolver() {
            var mxRecords = new TaskCompletionSource<DnsAnswer[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var healthCheck = new DomainHealthCheck {
                DnsConfiguration = new DnsConfiguration {
                    QueryDnsOverride = (_, _) => mxRecords.Task
                }
            };
            Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> firstResolver =
                (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback });
            Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> secondResolver =
                (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback });
            healthCheck.SmtpTlsAnalysis.AddressFamily = MailTransportAddressFamily.IPv4;
            healthCheck.SmtpTlsAnalysis.OutboundAddressResolver = firstResolver;

            var first = healthCheck.VerifySMTPTLS("example.com", 25);
            var repeated = healthCheck.VerifySMTPTLS("example.com", 25);
            healthCheck.SmtpTlsAnalysis.AddressFamily = MailTransportAddressFamily.IPv6;
            var differentFamily = healthCheck.VerifySMTPTLS("example.com", 25);
            healthCheck.SmtpTlsAnalysis.OutboundAddressResolver = secondResolver;
            var differentResolver = healthCheck.VerifySMTPTLS("example.com", 25);

            Assert.Same(first, repeated);
            Assert.NotSame(first, differentFamily);
            Assert.NotSame(differentFamily, differentResolver);
            mxRecords.SetResult(Array.Empty<DnsAnswer>());
            await Task.WhenAll(first, differentFamily, differentResolver);
        }

        [Fact]
        public async Task MxMailProbesPreserveAnalysisResolversWhenTopLevelResolverIsUnset() {
            var healthCheck = CreateHealthCheckWithEmptyMx();
            Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>> resolver =
                (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback });
            healthCheck.StartTlsAnalysis.OutboundAddressResolver = resolver;
            healthCheck.SmtpTlsAnalysis.OutboundAddressResolver = resolver;
            healthCheck.ImapTlsAnalysis.OutboundAddressResolver = resolver;
            healthCheck.Pop3TlsAnalysis.OutboundAddressResolver = resolver;

            await healthCheck.VerifySTARTTLS("example.com");
            await healthCheck.VerifySMTPTLS("example.com");
            await healthCheck.VerifyIMAPTLS("example.com");
            await healthCheck.VerifyPOP3TLS("example.com");

            Assert.Same(resolver, healthCheck.StartTlsAnalysis.OutboundAddressResolver);
            Assert.Same(resolver, healthCheck.SmtpTlsAnalysis.OutboundAddressResolver);
            Assert.Same(resolver, healthCheck.ImapTlsAnalysis.OutboundAddressResolver);
            Assert.Same(resolver, healthCheck.Pop3TlsAnalysis.OutboundAddressResolver);
        }

        private static DomainHealthCheck CreateHealthCheckWithEmptyMx() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.DnsConfiguration = new DnsConfiguration {
                QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>())
            };
            return healthCheck;
        }
    }
}
