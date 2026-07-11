using DnsClientX;

namespace DomainDetective.Tests {
    public class TestDkimSelectors {
        [Fact]
        public async Task ExplicitSelectorAcceptsKeyWithoutOptionalVersionTag() {
            const string record = "k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            var healthCheck = new DomainHealthCheck();
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(
                name == "selector._domainkey.example.com" && type == DnsRecordType.TXT
                    ? new[] { new DnsAnswer { Name = name, Type = type, DataRaw = record } }
                    : Array.Empty<DnsAnswer>());

            await healthCheck.VerifyDKIM("example.com", new[] { "selector" });

            var result = Assert.Single(healthCheck.DKIMAnalysis.AnalysisResults).Value;
            Assert.False(result.VersionTagPresent);
            Assert.True(result.VersionValid);
            Assert.True(result.ValidPublicKey);
        }

        [Fact]
        public async Task EmptySelectorsAreIgnored() {
            var healthCheck = new DomainHealthCheck(DnsEndpoint.CloudflareWireFormat) { Verbose = false };
            await healthCheck.VerifyDKIM("evotec.pl", new[] { " selector1 ", "", " \t", "selector2" });
            if (healthCheck.DKIMAnalysis.AnalysisResults.Count == 0) {
                return;
            }

            Assert.Equal(2, healthCheck.DKIMAnalysis.AnalysisResults.Count);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector1"));
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector2"));
            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey(" selector1 "));
        }
    }
}
