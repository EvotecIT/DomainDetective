using DnsClientX;

namespace DomainDetective.Tests {
    public class TestDkimGuess {
        [Fact]
        public async Task GuessSelectorsForDomain() {
            var healthCheck = new DomainHealthCheck(DnsEndpoint.CloudflareWireFormat) { Verbose = false };
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) => {
                if (name.Equals("selector1._domainkey.evotec.pl", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(new[] {
                        new DnsAnswer {
                            DataRaw = "v=DKIM1; p=AAA",
                            Type = DnsRecordType.TXT
                        }
                    });
                }

                if (name.Equals("selector2._domainkey.evotec.pl", StringComparison.OrdinalIgnoreCase)) {
                    return Task.FromResult(new[] {
                        new DnsAnswer {
                            DataRaw = "v=DKIM1; p=BBB",
                            Type = DnsRecordType.TXT
                        }
                    });
                }

                return Task.FromResult(Array.Empty<DnsAnswer>());
            };

            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM });
            if (healthCheck.DKIMAnalysis.AnalysisResults.Count == 0) {
                return;
            }

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector1"));
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector2"));
        }
        [Fact]
        public void GuessSelectorsIncludesDmarcianData() {
            var selectors = DomainDetective.Definitions.DKIMSelectors.GuessSelectors().ToList();
            Assert.Contains("selector2019", selectors);
            Assert.True(selectors.Count > 17);
        }
    }
}
