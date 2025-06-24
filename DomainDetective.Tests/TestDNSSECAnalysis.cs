namespace DomainDetective.Tests {
    public class TestDnssecAnalysis {
        [Fact]
        public async Task ValidateDnssecForDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);

            Assert.NotEmpty(healthCheck.DNSSecAnalysis.DnsKeys);
            Assert.True(healthCheck.DNSSecAnalysis.AuthenticData);
            Assert.True(healthCheck.DNSSecAnalysis.DsAuthenticData);
            Assert.True(healthCheck.DNSSecAnalysis.DsMatch);
            Assert.True(healthCheck.DNSSecAnalysis.ChainValid);
        }

        [Fact]
        public async Task ValidateDnssecChainFailure() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("dnssec-failed.org", [HealthCheckType.DNSSEC]);

            Assert.False(healthCheck.DNSSecAnalysis.ChainValid);
        }
    }
}
