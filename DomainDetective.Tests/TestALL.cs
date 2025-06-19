namespace DomainDetective.Tests {
    public class TestAll {
        [Fact]
        public async Task TestAllHealthChecks() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.Verify("evotec.pl", [HealthCheckType.DMARC, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.CAA], ["selector1", "selector2"]);

            Assert.True(healthCheck.DmarcAnalysis.Pct == 100);
            Assert.True(healthCheck.DmarcAnalysis.PolicyShort == "reject");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua.Count == 3);
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[0] == "1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[1] == "7kkoc19n@ag.eu.dmarcian.com");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[2] == "dmarc@evotec.pl");
            Assert.True(healthCheck.DmarcAnalysis.DkimAShort == "s");
            Assert.True(healthCheck.DmarcAnalysis.SpfAShort == "s");

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].DkimRecordExists == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].Flags == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].HashAlgorithm == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].KeyType == "rsa");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector1"].StartsCorrectly == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].DkimRecordExists == true);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].Flags == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].HashAlgorithm == null);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyType == "rsa");
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].PublicKeyExists);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].StartsCorrectly);
            Assert.True(healthCheck.DKIMAnalysis.AnalysisResults["selector2"].KeyTypeExists);

            Assert.True(healthCheck.SpfAnalysis.SpfRecordExists);
            Assert.False(healthCheck.SpfAnalysis.MultipleSpfRecords);
            Assert.True(healthCheck.SpfAnalysis.HasNullLookups == false);
            Assert.True(healthCheck.SpfAnalysis.ExceedsDnsLookups == false);
            Assert.True(healthCheck.SpfAnalysis.MultipleAllMechanisms == false);
            Assert.True(healthCheck.SpfAnalysis.ContainsCharactersAfterAll == false);
            Assert.True(healthCheck.SpfAnalysis.HasPtrType == false);
            Assert.True(healthCheck.SpfAnalysis.StartsCorrectly == true);
            Assert.True(healthCheck.SpfAnalysis.ExceedsCharacterLimit == false);

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults.Count == 8);
            Assert.True(healthCheck.CAAAnalysis.Valid == true);
            Assert.True(healthCheck.CAAAnalysis.Conflicting == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.CanIssueMail.Count == 0);
            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count == 4);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count == 4);
        }
    }
}
