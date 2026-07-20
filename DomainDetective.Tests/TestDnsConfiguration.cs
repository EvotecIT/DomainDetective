using DnsClientX;
using DomainDetective;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsConfiguration {
        [Fact]
        public async Task QueryFullDNSThrowsIfNamesNull() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryFullDNS(null!, DnsRecordType.A));
        }

        [Fact]
        public async Task QueryFullDNSThrowsIfNamesEmpty() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryFullDNS(Array.Empty<string>(), DnsRecordType.A));
        }

        [Fact]
        public async Task QueryDNSThrowsIfNameNull() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryDNS((string)null!, DnsRecordType.A));
        }

        [Fact]
        public async Task QueryDNSThrowsIfNameEmpty() {
            var config = new DnsConfiguration();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await config.QueryDNS(string.Empty, DnsRecordType.A));
        }

        [Fact]
        public async Task FilteredFullResponsePreservesDnsMetadata() {
            var original = new DnsResponse {
                Status = DnsResponseCode.NoError,
                AuthenticData = true,
                Error = "diagnostic",
                Questions = new[] { new DnsQuestion { Name = "example.com", OriginalName = "example.com", Type = DnsRecordType.TXT } },
                Answers = new[] {
                    new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, DataRaw = "keep-this" },
                    new DnsAnswer { Name = "example.com", Type = DnsRecordType.TXT, DataRaw = "drop-this" }
                },
                Authorities = new[] { new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, DataRaw = "ns.example.com" } }
            };
            var config = new DnsConfiguration {
                QueryDnsResponseOverride = (_, _, _) => Task.FromResult(original)
            };

            DnsResponse response = (await config.QueryFullDNS(
                new[] { "example.com" }, DnsRecordType.TXT, "keep")).Single();

            Assert.NotSame(original, response);
            Assert.Equal(DnsResponseCode.NoError, response.Status);
            Assert.True(response.AuthenticData);
            Assert.Equal("diagnostic", response.Error);
            Assert.Single(response.Questions);
            Assert.Single(response.Authorities);
            Assert.Single(response.Answers);
            Assert.Equal("keep-this", response.Answers[0].DataRaw);
        }

        [Fact]
        public async Task ResponseOverrideReceivesCallerCancellation() {
            using var cancellation = new CancellationTokenSource();
            var config = new DnsConfiguration {
                QueryDnsResponseOverride = async (_, _, token) => {
                    await Task.Delay(Timeout.Infinite, token);
                    return new DnsResponse();
                }
            };

            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                config.QueryDNS("example.com", DnsRecordType.A, cancellationToken: cancellation.Token));
        }

        [Fact]
        public async Task DomainHealthCheckOwnsAndReplacesDnsConfiguration() {
            var healthCheck = new DomainHealthCheck();
            DnsConfiguration original = healthCheck.DnsConfiguration;
            var replacement = new DnsConfiguration();

            healthCheck.DnsConfiguration = replacement;

            Assert.Same(replacement, healthCheck.MXAnalysis.DnsConfiguration);
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                original.QueryDNS("example.com", DnsRecordType.A));

            healthCheck.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                replacement.QueryDNS("example.com", DnsRecordType.A));
        }
    }
}
