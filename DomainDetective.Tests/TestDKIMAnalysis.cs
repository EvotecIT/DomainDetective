using DnsClientX;

namespace DomainDetective.Tests {
    public class TestDkimAnalysis {
        [Fact]
        public async Task TestDKIMRecord() {
            var dkimRecord = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;";
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = true;
            await healthCheck.CheckDKIM(dkimRecord);
            foreach (var selector in healthCheck.DKIMAnalysis.AnalysisResults.Keys) {
                Assert.Equal("default", selector);
                Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults[selector].Name);
                Assert.Equal(dkimRecord, healthCheck.DKIMAnalysis.AnalysisResults[selector].DkimRecord);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].DkimRecordExists);
                Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults[selector].Flags);
                Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults[selector].HashAlgorithm);
                Assert.Equal("rsa", healthCheck.DKIMAnalysis.AnalysisResults[selector].KeyType);
                Assert.Equal("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB", healthCheck.DKIMAnalysis.AnalysisResults[selector].PublicKey);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].PublicKeyExists);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].ValidPublicKey);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].ValidRsaKeyLength);
                Assert.Equal(1024, healthCheck.DKIMAnalysis.AnalysisResults[selector].KeyLength);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].StartsCorrectly);
                Assert.True(healthCheck.DKIMAnalysis.AnalysisResults[selector].KeyTypeExists);
            }
        }

        [Fact]
        public async Task TestDKIMByDomain() {
            var healthCheck = new DomainHealthCheck {
                Verbose = true
            };
            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.DKIM }, new[] { "selector1", "selector2" });

            Assert.Equal("selector1-evotec-pl._domainkey.evotecpoland.onmicrosoft.com", healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Name);
            Assert.Equal("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;", healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecord);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecordExists);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Flags);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].HashAlgorithm);
            Assert.Equal("rsa", healthCheck.DKIMAnalysis.AnalysisResults["selector1"].KeyType);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].StartsCorrectly);
            Assert.Equal("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB", healthCheck.DKIMAnalysis.AnalysisResults["selector1"].PublicKey);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].PublicKeyExists);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].ValidPublicKey);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].ValidRsaKeyLength);
            Assert.Equal(1024, healthCheck.DKIMAnalysis.AnalysisResults["selector1"].KeyLength);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Name == "selector2-evotec-pl._domainkey.evotecpoland.onmicrosoft.com");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecord == "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21OfspkRgPHhdCgu3kWgBX+xLyw7wRqM+Y4KaX82Pul9ikEDfZCJ35siFzV2WMH9Od/yM2TtMnubRqm9QN6paEB0VhNgNURQMmyTVsBO1usTJS9IvkIt3JtTFEinzVJLEaOC/F3d6bJaW9MMKUTBra9RcUf/E6dWAaJX8lrK8SefL9adNTwED8ZgFBnFcoJJn6e1W2WyIZ/8XAk+5Jwc7JMFZsdjFYdBSDPNyEfhNsKahVdRvdCG+OeDHyLSiNuFE27wtXaUI2TySDcfSSzE8k8z/Td9mMb0DQ2qaJ6xxk/5cwzwYSXr3sdGp++mHpGOJm18OwfsJmFCuSEcFGrHAQIDAQAB;");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecordExists == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Flags == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].HashAlgorithm == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyType == "rsa");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKey == "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA21OfspkRgPHhdCgu3kWgBX+xLyw7wRqM+Y4KaX82Pul9ikEDfZCJ35siFzV2WMH9Od/yM2TtMnubRqm9QN6paEB0VhNgNURQMmyTVsBO1usTJS9IvkIt3JtTFEinzVJLEaOC/F3d6bJaW9MMKUTBra9RcUf/E6dWAaJX8lrK8SefL9adNTwED8ZgFBnFcoJJn6e1W2WyIZ/8XAk+5Jwc7JMFZsdjFYdBSDPNyEfhNsKahVdRvdCG+OeDHyLSiNuFE27wtXaUI2TySDcfSSzE8k8z/Td9mMb0DQ2qaJ6xxk/5cwzwYSXr3sdGp++mHpGOJm18OwfsJmFCuSEcFGrHAQIDAQAB");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKeyExists);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].ValidPublicKey);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].ValidRsaKeyLength);
            Assert.Equal(2048, healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyLength);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].StartsCorrectly);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

        }

        [Fact]
        public async Task ConcatenateMultipleTxtChunks() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB",
                    Type = DnsRecordType.TXT
                },
                new DnsAnswer {
                    DataRaw = "iQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;",
                    Type = DnsRecordType.TXT
                }
            };

            var analysis = new DkimAnalysis();
            await analysis.AnalyzeDkimRecords("default", answers, new InternalLogger());

            Assert.True(analysis.AnalysisResults["default"].DkimRecordExists);
            Assert.Equal(
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;",
                analysis.AnalysisResults["default"].DkimRecord);
        }

        [Fact]
        public async Task ResetsBetweenRuns() {
            const string record1 = "v=DKIM1; k=rsa; p=AAAABBBB;";
            const string record2 = "v=DKIM1; k=rsa; p=CCCCDDDD;";

            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckDKIM(record1, "selector1");
            Assert.Single(healthCheck.DKIMAnalysis.AnalysisResults);
            Assert.Equal(record1, healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecord);

            await healthCheck.CheckDKIM(record2, "selector2");

            Assert.Single(healthCheck.DKIMAnalysis.AnalysisResults);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("selector2"));
            Assert.Equal(record2, healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecord);
        }

        [Fact]
        public async Task InvalidBase64PublicKeyIsFlagged() {
            const string record = "v=DKIM1; k=rsa; p=@@@badbase64;";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDKIM(record);

            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidPublicKey);
            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidRsaKeyLength);
            Assert.Equal(0, healthCheck.DKIMAnalysis.AnalysisResults["default"].KeyLength);
        }

        [Fact]
        public async Task ShortPublicKeyIsFlagged() {
            const string record = "v=DKIM1; k=rsa; p=QUJD;";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDKIM(record);

            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidPublicKey);
            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidRsaKeyLength);
            Assert.Equal(0, healthCheck.DKIMAnalysis.AnalysisResults["default"].KeyLength);
        }

        [Fact]
        public async Task InvalidKeyTypeIsFlagged() {
            const string record = "v=DKIM1; k=hmac; p=QUJD;";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDKIM(record);

            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidKeyType);
            Assert.Equal(0, healthCheck.DKIMAnalysis.AnalysisResults["default"].KeyLength);
        }

        [Fact]
        public async Task UnexpectedFlagCharactersDetected() {
            const string record = "v=DKIM1; t=yz; k=rsa; p=QUJD;";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDKIM(record);

            Assert.False(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidFlags);
            Assert.Contains("z", healthCheck.DKIMAnalysis.AnalysisResults["default"].UnknownFlagCharacters);
            Assert.Equal(0, healthCheck.DKIMAnalysis.AnalysisResults["default"].KeyLength);
        }

        [Fact]
        public async Task Large4096BitKeyIsValid() {
            const string key =
                "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApuPAMwNrEa/+qpJPsLDr" +
                "cr4rFjnsdaGmsKBjsm8aLzIX7WmYpTKAU8xC5FvsrCAoL4YLxBOeEvcje7hwR5yW" +
                "ncOyb7ZyqVAt5kRZp3MGZrfGll5Hv9+6YisIBM5GrfA0IJRJEZBhVjwNKX00Ae4S" +
                "AAF+8KKy+li9T2ubeBI2UGkOZy0T3QRUfcGAW7tZP4EX/ja8lhJ/0W+0u1VhMZtz" +
                "rA1ywN6kxLnnlgQ6z8oXvOw0O1Cy+2jqAUT2kY1lxpiVHbvV7RDw+mmRUKba4AQe" +
                "gxFdyYAzWNgbc34cH+QxbQ+Gxx9yM5GF975cKHIH972Q7MUeokQWS2hozodFQgcQ" +
                "/x2ntRbGTmZ5EHkH7k0SxoN2DwiOXkXey4d4OlFUmhi4GdT5Pe5DX82Wes7yf64g" +
                "n5YFilih2Z8j58w/YHcs1I28d0nESY1ZyYbnmqC5DwJkKYNiVlO2++B//xj+FYMd" +
                "j7DXJGF03fRQe2aGm70UOVEw+cDd1xuHw7G5NCUvnOj8eoOmaUp1TzMAjdXGUIsl" +
                "tY0/h/22dhNsktQWIO/s0HhxA/7es44UZh0y2KkD4c4hvOKzoFgXzV6L8U2hTOC9" +
                "PzGa4yV4U0RxoB3oKoVghD2mCX7ajU7yFtBa1iqpJ8Ez8Y6VS8xJqHo7fCPDvsZ4" +
                "3lTr1DdO07FUi0QOCf/+BIsCAwEAAQ==";

            string record = $"v=DKIM1; k=rsa; p={key};";

            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDKIM(record);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidPublicKey);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["default"].ValidRsaKeyLength);
            Assert.Equal(4096, healthCheck.DKIMAnalysis.AnalysisResults["default"].KeyLength);
        }
    }
}