using System;
using System.IO;
using System.Linq;
using DnsClientX;
using DomainDetective;

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
            Assert.Equal(500, healthCheck.DmarcAnalysis.OriginalPct);
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
            Assert.Equal(-1, healthCheck.DmarcAnalysis.OriginalPct);
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

        [Fact]
        public async Task DetectMissingExternalAuthorization() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = "v=DMARC1; p=none; rua=mailto:reports@external.com",
                    Type = DnsRecordType.TXT
                }
            };

            var list = PublicSuffixList.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
            var analysis = new DmarcAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>())
            };
            await analysis.AnalyzeDmarcRecords(answers, new InternalLogger(), "example.com", list.GetRegistrableDomain);

            Assert.True(analysis.ExternalReportAuthorization.ContainsKey("external.com"));
            Assert.False(analysis.ExternalReportAuthorization["external.com"]);
        }

        [Fact]
        public async Task WarnsOnMisalignedReportAddresses() {
            var record = new[] {
                new DnsAnswer {
                    DataRaw = "v=DMARC1; p=none; rua=mailto:reports@external.com",
                    Type = DnsRecordType.TXT
                }
            };

            var list = PublicSuffixList.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var analysis = new DmarcAnalysis { QueryDnsOverride = (_, _) => Task.FromResult(Array.Empty<DnsAnswer>()) };
            await analysis.AnalyzeDmarcRecords(record, logger, "example.com", list.GetRegistrableDomain);

            Assert.Contains(warnings, w => w.FullMessage.Contains("reports@external.com") && w.FullMessage.Contains("example.com"));
        }

        [Fact]
        public async Task InvalidAlignmentFlags() {
            var dmarcRecord = "v=DMARC1; p=none; adkim=x; aspf=y";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.False(healthCheck.DmarcAnalysis.ValidDkimAlignment);
            Assert.False(healthCheck.DmarcAnalysis.ValidSpfAlignment);
            Assert.Equal("x", healthCheck.DmarcAnalysis.DkimAShort);
            Assert.Equal("y", healthCheck.DmarcAnalysis.SpfAShort);
        }

        [Fact]
        public async Task BadUrisSetInvalidFlag() {
            var dmarcRecord = "v=DMARC1; p=none; rua=mailto:test@example.com,http://bad.example.com,mailto:invalid; ruf=https://reports.example.com";
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);
            await healthCheck.CheckDMARC(dmarcRecord);
            Assert.True(healthCheck.DmarcAnalysis.InvalidReportUri);
            Assert.Single(healthCheck.DmarcAnalysis.MailtoRua);
            Assert.Equal("test@example.com", healthCheck.DmarcAnalysis.MailtoRua[0]);
            Assert.Single(healthCheck.DmarcAnalysis.HttpRuf);
            Assert.Equal("https://reports.example.com", healthCheck.DmarcAnalysis.HttpRuf[0]);
            Assert.Contains(warnings, w => w.FullMessage.Contains("HTTP instead of HTTPS"));
        }

        [Fact]
        public async Task MissingSchemeTriggersWarning() {
            var dmarcRecord = "v=DMARC1; p=none; rua=reports.example.com";
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);
            await healthCheck.CheckDMARC(dmarcRecord);

            Assert.True(healthCheck.DmarcAnalysis.InvalidReportUri);
            Assert.Empty(healthCheck.DmarcAnalysis.MailtoRua);
            Assert.Empty(healthCheck.DmarcAnalysis.HttpRua);
            Assert.Contains(warnings, w => w.FullMessage.Contains("missing a scheme"));
        }

        [Fact]
        public async Task RufSizeWarningWhenTooLarge() {
            var dmarcRecord = "v=DMARC1; p=none; ruf=mailto:reports@example.com!20m";
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);

            await healthCheck.CheckDMARC(dmarcRecord);

            Assert.Single(healthCheck.DmarcAnalysis.MailtoRuf);
            Assert.Equal("reports@example.com", healthCheck.DmarcAnalysis.MailtoRuf[0]);
            Assert.Single(healthCheck.DmarcAnalysis.RufSizeLimits);
            Assert.Equal(20 * 1024 * 1024, healthCheck.DmarcAnalysis.RufSizeLimits[0]);
            Assert.Contains(warnings, w => w.FullMessage.Contains("10MB"));
        }

        [Fact]
        public async Task PercentEncodedAddressesAreDecoded() {
            var record = "v=DMARC1; p=none; rua=mailto:test%2Balias@example.com; ruf=mailto:test%2Bforensic@example.com";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckDMARC(record);

            Assert.Contains("test+alias@example.com", healthCheck.DmarcAnalysis.MailtoRua);
            Assert.Contains("test+forensic@example.com", healthCheck.DmarcAnalysis.MailtoRuf);
        }

        [Fact]
        public async Task InvalidSchemeSetsFlag() {
            var record = "v=DMARC1; p=none; rua=ftp://reports.example.com";
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);

            await healthCheck.CheckDMARC(record);

            Assert.True(healthCheck.DmarcAnalysis.InvalidReportUri);
            Assert.Empty(healthCheck.DmarcAnalysis.MailtoRua);
            Assert.Empty(healthCheck.DmarcAnalysis.HttpRua);
            Assert.Contains(warnings, w => w.FullMessage.Contains("missing a scheme"));
        }

        [Fact]
        public async Task UnknownTagsAreCollected() {
            var dmarcRecord = "v=DMARC1; p=none; foo=bar; test; x=y";
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckDMARC(dmarcRecord);

            Assert.Contains("foo=bar", healthCheck.DmarcAnalysis.UnknownTags);
            Assert.Contains("test", healthCheck.DmarcAnalysis.UnknownTags);
            Assert.Contains("x=y", healthCheck.DmarcAnalysis.UnknownTags);
        }

        [Fact]
        public async Task DetectMultipleRecords() {
            var answers = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "v=DMARC1; p=none", Type = DnsRecordType.TXT },
                new DnsAnswer { DataRaw = "v=DMARC1; p=quarantine", Type = DnsRecordType.TXT }
            };

            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(answers, new InternalLogger());

            Assert.True(analysis.MultipleRecords);
        }

        [Fact]
        public async Task AlignmentStrictVsRelaxed() {
            var list = PublicSuffixList.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));

            var strictRecord = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "v=DMARC1; p=reject; adkim=s; aspf=s", Type = DnsRecordType.TXT }
            };
            var analysisStrict = new DmarcAnalysis();
            await analysisStrict.AnalyzeDmarcRecords(strictRecord, new InternalLogger());
            analysisStrict.EvaluateAlignment("mail.example.com", "bounce.example.com", "example.com", list.GetRegistrableDomain);
            Assert.False(analysisStrict.SpfAligned);
            Assert.False(analysisStrict.DkimAligned);

            var relaxedRecord = new List<DnsAnswer> {
                new DnsAnswer { DataRaw = "v=DMARC1; p=reject; adkim=r; aspf=r", Type = DnsRecordType.TXT }
            };
            var analysisRelaxed = new DmarcAnalysis();
            await analysisRelaxed.AnalyzeDmarcRecords(relaxedRecord, new InternalLogger());
            analysisRelaxed.EvaluateAlignment("mail.example.com", "bounce.example.com", "example.com", list.GetRegistrableDomain);
            Assert.True(analysisRelaxed.SpfAligned);
            Assert.True(analysisRelaxed.DkimAligned);
        }

        [Fact]
        public async Task AlignmentUsesPublicSuffixForMultiLabelTld() {
            var list = PublicSuffixList.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public_suffix_list.dat"));
            var record = new[] { new DnsAnswer { DataRaw = "v=DMARC1; p=reject", Type = DnsRecordType.TXT } };
            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(record, new InternalLogger());

            analysis.EvaluateAlignment("mail.example.co.uk", "bounce.example.co.uk", "example.co.uk", list.GetRegistrableDomain);

            Assert.True(analysis.SpfAligned);
            Assert.True(analysis.DkimAligned);
        }

        [Theory]
        [InlineData("v=DMARC1; p=none", false, true)]
        [InlineData("v=DMARC1; p=quarantine", false, false)]
        [InlineData("v=DMARC1; p=reject; sp=none", true, true)]
        public async Task EvaluatePolicyStrengthFlagsWeakPolicy(string record, bool checkSub, bool expected) {
            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(new[] { new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT } }, new InternalLogger());
            analysis.EvaluatePolicyStrength(checkSub);

            Assert.Equal(expected, analysis.WeakPolicy);
            if (expected) {
                Assert.Equal("Consider quarantine or reject.", analysis.PolicyRecommendation);
            } else {
                Assert.Equal(string.Empty, analysis.PolicyRecommendation);
            }
        }

        [Fact]
        public async Task AlignmentModeTranslation() {
            var record = new[] {
                new DnsAnswer { DataRaw = "v=DMARC1; p=reject; adkim=s; aspf=r", Type = DnsRecordType.TXT }
            };

            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(record, new InternalLogger());

            Assert.Equal("Strict", analysis.DkimAlignment);
            Assert.Equal("Relaxed", analysis.SpfAlignment);

            var defaultRecord = new[] {
                new DnsAnswer { DataRaw = "v=DMARC1; p=reject", Type = DnsRecordType.TXT }
            };
            var analysisDefault = new DmarcAnalysis();
            await analysisDefault.AnalyzeDmarcRecords(defaultRecord, new InternalLogger());

            Assert.Equal("Relaxed (defaulted)", analysisDefault.DkimAlignment);
            Assert.Equal("Relaxed (defaulted)", analysisDefault.SpfAlignment);
        }

        [Fact]
        public async Task SubPolicyDefaultsToDomainPolicy() {
            var record = new[] {
                new DnsAnswer { DataRaw = "v=DMARC1; p=quarantine", Type = DnsRecordType.TXT }
            };

            var analysis = new DmarcAnalysis();
            await analysis.AnalyzeDmarcRecords(record, new InternalLogger());

            Assert.Equal("quarantine", analysis.PolicyShort);
            Assert.Null(analysis.SubPolicyShort);
            Assert.Equal("Quarantine (inherited)", analysis.SubPolicy);
        }

        [Fact]
        public async Task TrailingWhitespaceNotCountedTowardsLimit() {
            var record = "v=DMARC1; p=none " + new string('a', 238) + "  ";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(record);

            Assert.False(healthCheck.DmarcAnalysis.ExceedsCharacterLimit);
        }

        [Fact]
        public async Task ExceedsCharacterLimitWhenTrimmed() {
            var record = "v=DMARC1; p=none " + new string('a', 239);
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckDMARC(record);

            Assert.True(healthCheck.DmarcAnalysis.ExceedsCharacterLimit);
        }

        [Fact]
        public async Task InvalidReportingIntervalDefaultsToOneDay() {
            var record = "v=DMARC1; p=none; ri=bad";
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);

            await healthCheck.CheckDMARC(record);

            Assert.Equal("86400", healthCheck.DmarcAnalysis.ReportingIntervalShort);
            Assert.Contains(warnings, w => w.FullMessage.Contains("Invalid reporting interval"));
            Assert.Equal("1 days", healthCheck.DmarcAnalysis.ReportingInterval);
        }
    }
}
