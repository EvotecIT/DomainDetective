namespace DomainDetective.Tests {
    public class TestDomainSummary {
        [Fact]
        public void SummaryWithoutDnsSecReturnsFalse() {
            var healthCheck = new DomainHealthCheck();
            var filtered = healthCheck.FilterAnalyses(new[] {
                HealthCheckType.SPF, HealthCheckType.DMARC,
                HealthCheckType.DKIM, HealthCheckType.MX
            });

            var summary = filtered.BuildSummary();

            Assert.False(summary.DnsSecValid);
        }

        [Fact]
        public void SummaryUsesDnsSecResultWhenAvailable() {
            var healthCheck = new DomainHealthCheck();
            var prop = typeof(DNSSecAnalysis).GetProperty(
                "ChainValid",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public
            )!;
            prop.SetValue(healthCheck.DNSSecAnalysis, true);

            var summary = healthCheck.BuildSummary();

            Assert.True(summary.DnsSecValid);
        }
    }
}
