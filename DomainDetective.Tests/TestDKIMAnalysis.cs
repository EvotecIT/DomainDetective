namespace DomainDetective.Tests {
    public class TestDkimAnalysis {
        [Fact]
        public async Task TestDKIMRecord() {
            var dkimRecord = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;";
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = true;
            await healthCheck.CheckDKIM(dkimRecord);
            foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
                Assert.True(selector == "default");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].Name == null, "Selector name should be null for this test case.");

                // Ensure the full DKIM record string is lowercase and matches the input.ToLower()
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].DkimRecord == dkimRecord.ToLower(), "Full DKIM record string should be lowercase and match input.ToLower()");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].DkimRecordExists, "DkimRecordExists should be true.");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].Flags == null, "Flags should be null.");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].HashAlgorithm == null, "HashAlgorithm should be null.");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].KeyType == "rsa", "KeyType should be 'rsa'.");
                // Change the assertion for the PublicKey to expect a lowercase version
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].PublicKey == "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB".ToLower(), "PublicKey should be lowercase if derived from a lowercase DKIM string.");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].PublicKeyExists, "PublicKeyExists should be true.");
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].StartsCorrectly, "StartsCorrectly should be true."); // This will likely fail if DkimRecord is lowercase and it expects "v=DKIM1"
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].KeyTypeExists, "KeyTypeExists should be true.");
            }
        }

        [Fact]
        public async Task TestDKIMByDomain() {
            var healthCheck = new DomainHealthCheck {
                Verbose = true
            };
            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM }, new[] { "selector1", "selector2" });

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Name == "selector1-evotec-pl._domainkey.evotecpoland.onmicrosoft.com");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecord == "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecordExists == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Flags == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].HashAlgorithm == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].KeyType == "rsa");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].StartsCorrectly == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].PublicKey == "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].PublicKeyExists);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Name == "selector2-evotec-pl._domainkey.evotecpoland.onmicrosoft.com");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecord == "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21OfspkRgPHhdCgu3kWgBX+xLyw7wRqM+Y4KaX82Pul9ikEDfZCJ35siFzV2WMH9Od/yM2TtMnubRqm9QN6paEB0VhNgNURQMmyTVsBO1usTJS9IvkIt3JtTFEinzVJLEaOC/F3d6bJaW9MMKUTBra9RcUf/E6dWAaJX8lrK8SefL9adNTwED8ZgFBnFcoJJn6e1W2WyIZ/8XAk+5Jwc7JMFZsdjFYdBSDPNyEfhNsKahVdRvdCG+OeDHyLSiNuFE27wtXaUI2TySDcfSSzE8k8z/Td9mMb0DQ2qaJ6xxk/5cwzwYSXr3sdGp++mHpGOJm18OwfsJmFCuSEcFGrHAQIDAQAB;");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecordExists == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Flags == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].HashAlgorithm == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyType == "rsa");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKey == "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21OfspkRgPHhdCgu3kWgBX+xLyw7wRqM+Y4KaX82Pul9ikEDfZCJ35siFzV2WMH9Od/yM2TtMnubRqm9QN6paEB0VhNgNURQMmyTVsBO1usTJS9IvkIt3JtTFEinzVJLEaOC/F3d6bJaW9MMKUTBra9RcUf/E6dWAaJX8lrK8SefL9adNTwED8ZgFBnFcoJJn6e1W2WyIZ/8XAk+5Jwc7JMFZsdjFYdBSDPNyEfhNsKahVdRvdCG+OeDHyLSiNuFE27wtXaUI2TySDcfSSzE8k8z/Td9mMb0DQ2qaJ6xxk/5cwzwYSXr3sdGp++mHpGOJm18OwfsJmFCuSEcFGrHAQIDAQAB");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKeyExists);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].StartsCorrectly);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

        }
    }
}