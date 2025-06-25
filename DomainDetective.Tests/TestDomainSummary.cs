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

        [Fact]
        public async Task BuildSummaryIncludesValidityFlags() {
            const string spfRecord = "v=spf1 include:_spf.google.com -all";
            const string dmarcRecord = "v=DMARC1; p=reject;";
            const string dkimRecord = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckSPF(spfRecord);
            await healthCheck.CheckDMARC(dmarcRecord);
            await healthCheck.CheckDKIM(dkimRecord);

            var summary = healthCheck.BuildSummary();

            Assert.True(summary.SpfValid);
            Assert.True(summary.DmarcValid);
            Assert.True(summary.DkimValid);
        }
    }
}
