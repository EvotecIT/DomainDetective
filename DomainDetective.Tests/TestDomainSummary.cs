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
            Assert.Contains("Sign zones and publish DS records.", summary.Hints);
        }

        [Fact]
        public void SummaryUsesDnsSecResultWhenAvailable() {
            var healthCheck = new DomainHealthCheck();
            var prop = typeof(DnsSecAnalysis).GetProperty(
                "ChainValid",
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public
            )!;
            prop.SetValue(healthCheck.DnsSecAnalysis, true);

            var summary = healthCheck.BuildSummary();

            Assert.True(summary.DnsSecValid);

        }

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
            Assert.Empty(summary.Hints);
        }

        [Fact]
        public void SummaryProvidesHintsWhenChecksFail() {
            var healthCheck = new DomainHealthCheck();
            var summary = healthCheck.BuildSummary();

            Assert.Contains("Add or correct the SPF TXT record.", summary.Hints);
            Assert.Contains("Publish a valid DMARC record.", summary.Hints);
            Assert.Contains("Ensure DKIM selectors have valid keys.", summary.Hints);
        }
    }
}
