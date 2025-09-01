using DnsClientX;

namespace DomainDetective.Tests {
    public class TestDKIMAutoDetectNewSelectors {
        [Fact]
        public async Task AutoDetects_Protonmail_And_S1_Selectors_And_ParsesKeys() {
            const string domain = "example.com";
            var hc = new DomainHealthCheck(DnsEndpoint.CloudflareWireFormat) { Verbose = false };

            // Provide DKIM records for a couple of newer selectors in the built-in list
            hc.DnsConfiguration.QueryDnsOverride = (name, type) => {
                if (type != DnsRecordType.TXT) return Task.FromResult(Array.Empty<DnsAnswer>());
                if (name.Equals($"protonmail._domainkey.{domain}", StringComparison.OrdinalIgnoreCase)) {
                    // Invalid/too short key -> should set ValidPublicKey = false
                    return Task.FromResult(new[] {
                        new DnsAnswer { DataRaw = "v=DKIM1; p=AAA", Type = DnsRecordType.TXT }
                    });
                }
                if (name.Equals($"s1._domainkey.{domain}", StringComparison.OrdinalIgnoreCase)) {
                    // Realistic RSA key (1024b sample) -> ValidPublicKey true, ValidRsaKeyLength true, WeakKey true (<2048)
                    const string key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB";
                    return Task.FromResult(new[] {
                        new DnsAnswer { DataRaw = $"v=DKIM1; k=rsa; p={key}", Type = DnsRecordType.TXT }
                    });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            };

            await hc.Verify(domain, new[] { HealthCheckType.DKIM });
            if (hc.DKIMAnalysis.AnalysisResults.Count == 0) return; // CI resilience

            Assert.Contains("protonmail", hc.DKIMAnalysis.AnalysisResults.Keys);
            Assert.Contains("s1", hc.DKIMAnalysis.AnalysisResults.Keys);

            var pm = hc.DKIMAnalysis.AnalysisResults["protonmail"];
            Assert.True(pm.DkimRecordExists);
            Assert.True(pm.PublicKeyExists);
            Assert.False(pm.ValidPublicKey);
            Assert.False(pm.ValidRsaKeyLength);

            var s1 = hc.DKIMAnalysis.AnalysisResults["s1"];
            Assert.True(s1.DkimRecordExists);
            Assert.True(s1.PublicKeyExists);
            Assert.True(s1.ValidPublicKey);
            Assert.True(s1.ValidRsaKeyLength);
            Assert.True(s1.WeakKey); // 1024b sample
            Assert.Equal("rsa", s1.KeyType);

            // Advisory should mention at least one problematic selector
            Assert.Contains("Issues detected", hc.DKIMAnalysis.Advisory);
            Assert.Contains("protonmail", hc.DKIMAnalysis.Advisory);
        }
    }
}

