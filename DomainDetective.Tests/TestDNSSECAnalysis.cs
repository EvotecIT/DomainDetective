namespace DomainDetective.Tests {
    public class TestDnssecAnalysis {
        [Fact]
        public async Task ValidateDnssecForDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);

            Assert.NotEmpty(healthCheck.DnsSecAnalysis.DnsKeys);
            Assert.True(healthCheck.DnsSecAnalysis.AuthenticData);
            Assert.True(healthCheck.DnsSecAnalysis.DsAuthenticData);
            Assert.True(healthCheck.DnsSecAnalysis.DsMatch);
            Assert.True(healthCheck.DnsSecAnalysis.ChainValid);
            Assert.NotEmpty(healthCheck.DnsSecAnalysis.DsTtls);
            Assert.NotEmpty(healthCheck.DnsSecAnalysis.Rrsigs);
        }

        [Fact]
        public async Task ValidateDnssecChainFailure() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("dnssec-failed.org", [HealthCheckType.DNSSEC]);

            Assert.False(healthCheck.DnsSecAnalysis.ChainValid);
        }
    }
}