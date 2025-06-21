namespace DomainDetective.Tests {
    public class TestDnssecAnalysis {
        [Fact]
        public async Task ValidateDnssecForDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);

            Assert.NotEmpty(healthCheck.DNSSecAnalysis.DnsKeys);
            Assert.True(healthCheck.DNSSecAnalysis.AuthenticData);
            Assert.True(healthCheck.DNSSecAnalysis.DsMatch);
        }
    }
}
