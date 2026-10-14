using DnsClientX;
using System.Collections.Generic;

namespace DomainDetective.Tests {
    public class TestAll {
        [Fact]
        public async Task TestAllHealthChecks() {
            var records = new Dictionary<(string, DnsRecordType), DnsAnswer[]> {
                [("_dmarc.example.com", DnsRecordType.TXT)] = new[] { Answer(DnsRecordType.TXT,
                    "v=DMARC1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:first@example.com,mailto:second@example.com,mailto:third@example.com") },
                [("example.com", DnsRecordType.TXT)] = new[] { Answer(DnsRecordType.TXT, "v=spf1 -all") },
                [("selector1._domainkey.example.com", DnsRecordType.TXT)] = new[] { Answer(DnsRecordType.TXT, "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;") },
                [("selector2._domainkey.example.com", DnsRecordType.TXT)] = new[] { Answer(DnsRecordType.TXT, "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqrIpQkyykYEQbNzvHfgGsiYfoyX3b3Z6CPMHa5aNn/Bd8skLaqwK9vj2fHn70DA+X67L/pV2U5VYDzb5AUfQeD6NPDwZ7zLRc0XtX+5jyHWhHueSQT8uo6acMA+9JrVHdRfvtlQo8Oag8SLIkhaUea3xqZpijkQR/qHmo3GIfnQIDAQAB;") },
                [("example.com", DnsRecordType.CAA)] = new[] {
                    Answer(DnsRecordType.CAA, "0 issue \"letsencrypt.org\""), Answer(DnsRecordType.CAA, "0 issuewild \"letsencrypt.org\""),
                    Answer(DnsRecordType.CAA, "0 issue \"sectigo.com\""), Answer(DnsRecordType.CAA, "0 issuewild \"sectigo.com\""),
                    Answer(DnsRecordType.CAA, "0 issue \"digicert.com\""), Answer(DnsRecordType.CAA, "0 issuewild \"digicert.com\""),
                    Answer(DnsRecordType.CAA, "0 issue \"pki.goog\""), Answer(DnsRecordType.CAA, "0 issuewild \"pki.goog\""),
                    Answer(DnsRecordType.CAA, "0 issue \"globalsign.com\""), Answer(DnsRecordType.CAA, "0 issuewild \"globalsign.com\"")
                }
            };
            var healthCheck = new DomainHealthCheck { Verbose = false };
            healthCheck.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(
                records.TryGetValue((name, type), out var answers) ? answers : Array.Empty<DnsAnswer>());

            await healthCheck.Verify(
                "example.com",
                [HealthCheckType.DMARC, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.CAA],
                ["selector1", "selector2"]);

            Assert.Equal(100, healthCheck.DmarcAnalysis.Pct);
            Assert.Equal("reject", healthCheck.DmarcAnalysis.PolicyShort);
            Assert.Equal(3, healthCheck.DmarcAnalysis.MailtoRua.Count);
            Assert.Equal("first@example.com", healthCheck.DmarcAnalysis.MailtoRua[0]);
            Assert.Equal("second@example.com", healthCheck.DmarcAnalysis.MailtoRua[1]);
            Assert.Equal("third@example.com", healthCheck.DmarcAnalysis.MailtoRua[2]);
            Assert.Equal("s", healthCheck.DmarcAnalysis.DkimAShort);
            Assert.Equal("s", healthCheck.DmarcAnalysis.SpfAShort);

            Assert.Equal(2, healthCheck.DKIMAnalysis.AnalysisResults.Count);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecordExists);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Flags);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].HashAlgorithm);
            Assert.Equal("rsa", healthCheck.DKIMAnalysis.AnalysisResults["selector1"].KeyType);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].StartsCorrectly);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecordExists);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Flags);
            Assert.Null(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].HashAlgorithm);
            Assert.Equal("rsa", healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyType);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKeyExists);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].StartsCorrectly);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

            Assert.True(healthCheck.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck.SpfAnalysis.MultipleSpfRecords);
            Assert.False(healthCheck.SpfAnalysis.HasNullLookups);
            Assert.False(healthCheck.SpfAnalysis.ExceedsDnsLookups);
            Assert.False(healthCheck.SpfAnalysis.MultipleAllMechanisms);
            Assert.False(healthCheck.SpfAnalysis.ContainsCharactersAfterAll);
            Assert.False(healthCheck.SpfAnalysis.HasPtrType);
            Assert.True(healthCheck.SpfAnalysis.StartsCorrectly);
            Assert.False(healthCheck.SpfAnalysis.ExceedsCharacterLimit);

            Assert.Equal(10, healthCheck.CAAAnalysis.AnalysisResults.Count);
            Assert.True(healthCheck.CAAAnalysis.Valid);
            Assert.False(healthCheck.CAAAnalysis.Conflicting);
            Assert.False(healthCheck.CAAAnalysis.ConflictingWildcardCertificateIssuance);
            Assert.False(healthCheck.CAAAnalysis.ConflictingCertificateIssuance);
            Assert.Empty(healthCheck.CAAAnalysis.CanIssueMail);
            Assert.Equal(5, healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count);
            Assert.Equal(5, healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count);
            Assert.False(healthCheck.CAAAnalysis.HasDuplicateIssuers);
        }

        private static DnsAnswer Answer(DnsRecordType type, string value) => new() { Type = type, DataRaw = value };
    }
}