namespace DomainDetective.Tests {
    public class TestAll {
        [Fact]
        public async Task TestAllHealthChecks() {
            var healthCheck = new DomainHealthCheck {
                Verbose = false
            };
            await healthCheck.Verify("evotec.pl", [HealthCheckType.DMARC, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.CAA], ["selector1", "selector2"]);

            Assert.Equal(100, healthCheck.DmarcAnalysis.Pct);
            Assert.Equal("reject", healthCheck.DmarcAnalysis.PolicyShort);
            Assert.Equal(3, healthCheck.DmarcAnalysis.MailtoRua.Count);
            Assert.Equal("1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net", healthCheck.DmarcAnalysis.MailtoRua[0]);
            Assert.Equal("7kkoc19n@ag.eu.dmarcian.com", healthCheck.DmarcAnalysis.MailtoRua[1]);
            Assert.Equal("dmarc@evotec.pl", healthCheck.DmarcAnalysis.MailtoRua[2]);
            Assert.Equal("s", healthCheck.DmarcAnalysis.DkimAShort);
            Assert.Equal("s", healthCheck.DmarcAnalysis.SpfAShort);

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
        }
    }
}