namespace TestMyDomain.Tests {
    public class TestDMARCAnalysis {

        [Fact]
        public async Task TestDMARCByString() {
            var dmarcRecord = "v=DMARC1; p=reject; rua=mailto:1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net,mailto:7kkoc19n@ag.eu.dmarcian.com,mailto:dmarc@evotec.pl; adkim=s; aspf=s;";
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = true;
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.True(healthCheck.DmarcAnalysis.Pct == 100);
            Assert.True(healthCheck.DmarcAnalysis.PolicyShort == "reject");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua.Count == 3);
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[0] == "1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[1] == "7kkoc19n@ag.eu.dmarcian.com");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[2] == "dmarc@evotec.pl");
            Assert.True(healthCheck.DmarcAnalysis.DkimAShort == "s");
            Assert.True(healthCheck.DmarcAnalysis.SpfAShort == "s");
        }

        [Fact]
        public async Task TestDMARCByDomain() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = true;
            await healthCheck.Verify("evotec.pl", [HealthCheckType.DMARC]);
            Assert.True(healthCheck.DmarcAnalysis.Pct == 100);
            Assert.True(healthCheck.DmarcAnalysis.PolicyShort == "reject");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua.Count == 3);
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[0] == "1012c7e7df7b474cb85c1c8d00cc1c1a@dmarc-reports.cloudflare.net");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[1] == "7kkoc19n@ag.eu.dmarcian.com");
            Assert.True(healthCheck.DmarcAnalysis.MailtoRua[2] == "dmarc@evotec.pl");
            Assert.True(healthCheck.DmarcAnalysis.DkimAShort == "s");
            Assert.True(healthCheck.DmarcAnalysis.SpfAShort == "s");
        }
    }
}
