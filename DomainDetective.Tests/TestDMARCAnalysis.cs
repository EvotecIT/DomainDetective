using DnsClientX;

namespace DomainDetective.Tests {
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

        [Fact]
        public async Task TestPercentOutOfRange() {
            var dmarcRecord = "v=DMARC1; p=none; pct=500";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.Equal(100, healthCheck.DmarcAnalysis.Pct);
            Assert.False(healthCheck.DmarcAnalysis.IsPctValid);
            Assert.Equal(
                "Percentage value must be between 0 and 100.",
                healthCheck.DmarcAnalysis.Percent);
        }

        [Fact]
        public async Task TestPercentNegative() {
            var dmarcRecord = "v=DMARC1; p=none; pct=-1";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.Equal(0, healthCheck.DmarcAnalysis.Pct);
            Assert.False(healthCheck.DmarcAnalysis.IsPctValid);
            Assert.Equal(
                "Percentage value must be between 0 and 100.",
                healthCheck.DmarcAnalysis.Percent);
        }

        [Fact]
        public async Task TestInvalidPolicy() {
            var dmarcRecord = "v=DMARC1; p=invalid";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.True(healthCheck.DmarcAnalysis.HasMandatoryTags);
            Assert.False(healthCheck.DmarcAnalysis.IsPolicyValid);
            Assert.Equal("invalid", healthCheck.DmarcAnalysis.PolicyShort);
            Assert.Equal("Unknown policy", healthCheck.DmarcAnalysis.Policy);
        }

        [Fact]
        public async Task TestMissingPolicyTag() {
            var dmarcRecord = "v=DMARC1; rua=mailto:test@example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.False(healthCheck.DmarcAnalysis.HasMandatoryTags);
        }

        [Fact]
        public async Task ConcatenateMultipleTxtChunks() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = "v=DMARC1; p=none;",
                    Type = DnsRecordType.TXT
                },
                new DnsAnswer {
                    DataRaw = "rua=mailto:test@example.com",
                    Type = DnsRecordType.TXT
                }
            };

            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(answers, new InternalLogger());

            Assert.True(analysis.DmarcRecordExists);
            Assert.Equal("v=DMARC1; p=none; rua=mailto:test@example.com", analysis.DmarcRecord);
            Assert.Equal("none", analysis.PolicyShort);
            Assert.Single(analysis.MailtoRua);
            Assert.Equal("test@example.com", analysis.MailtoRua[0]);
        }
    }
}