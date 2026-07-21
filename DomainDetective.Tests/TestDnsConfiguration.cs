using DnsClientX;
using DomainDetective;
using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsConfiguration {
        [Fact]
        public void StandaloneConfigurationUsesOperationScopedResolver() {
            var config = new DnsConfiguration();
            MethodInfo acquire = typeof(DnsConfiguration).GetMethod(
                "AcquireResolver", BindingFlags.Instance | BindingFlags.NonPublic)!;
            FieldInfo retained = typeof(DnsConfiguration).GetField(
                "_resolver", BindingFlags.Instance | BindingFlags.NonPublic)!;

            using var lease = (IDisposable)acquire.Invoke(config, null)!;

            Assert.Null(retained.GetValue(config));
        }

        [Fact]
        public void OwnedConfigurationCanRetainResolverUntilDisposal() {
            using var config = new DnsConfiguration { ReuseResolverClients = true };
            MethodInfo acquire = typeof(DnsConfiguration).GetMethod(
                "AcquireResolver", BindingFlags.Instance | BindingFlags.NonPublic)!;
            FieldInfo retained = typeof(DnsConfiguration).GetField(
                "_resolver", BindingFlags.Instance | BindingFlags.NonPublic)!;

            using var lease = (IDisposable)acquire.Invoke(config, null)!;

            Assert.NotNull(retained.GetValue(config));
        }

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

            Assert.True(original.ReuseResolverClients);

            healthCheck.DnsConfiguration = replacement;

            Assert.True(replacement.ReuseResolverClients);
            Assert.Same(replacement, healthCheck.MXAnalysis.DnsConfiguration);
            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                original.QueryDNS("example.com", DnsRecordType.A));

            healthCheck.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() =>
                replacement.QueryDNS("example.com", DnsRecordType.A));
        }
    }
}
