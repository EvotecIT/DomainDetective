using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCAAAnalysis {
        [Fact]
        public async Task TestCAARecordByList() {
            List<string> caaRecords = new List<string> {
                // Test CAA record one by one
                "0 issue \"digicert.com; cansignhttpexchanges=yes\"",
                "0 issue \"letsencrypt.org;validationmethods=dns-01\"",
                "0 issue \"pki.goog; cansignhttpexchanges=yes\"",
                "0 issuewild \"letsencrypt.org\"",
                "0 issue \"letsencrypt.org\"",
                "0 iodef \"mailto:example@example.com\"",
                "260 issue \";\"",
                "0 issue \"letsencrypt.org\"",
                "0 issuemail \";\""
            };
            var healthCheck = new DomainHealthCheck(DnsEndpoint.CloudflareWireFormat);
            healthCheck.Verbose = false;
            await healthCheck.CheckCAA(caaRecords);

            Assert.Equal(9, healthCheck.CAAAnalysis.AnalysisResults.Count);
            Assert.Equal(3, healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count);
            Assert.Equal("digicert.com", healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[0]);
            Assert.Equal("letsencrypt.org", healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[1]);
            Assert.Equal("pki.goog", healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[2]);
            Assert.True(healthCheck.CAAAnalysis.HasDuplicateIssuers);

            Assert.Single(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain);
            Assert.Equal("letsencrypt.org", healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain[0]);

            //  "0 issue \"digicert.com; cansignhttpexchanges=yes\""
            Assert.Equal("0", healthCheck.CAAAnalysis.AnalysisResults[0].Flag);
            Assert.Equal(CAATagType.Issue, healthCheck.CAAAnalysis.AnalysisResults[0].Tag);
            Assert.Equal("digicert.com; cansignhttpexchanges=yes", healthCheck.CAAAnalysis.AnalysisResults[0].Value);
            Assert.Equal("digicert.com", healthCheck.CAAAnalysis.AnalysisResults[0].Issuer);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidFlag);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueUnescapedQuotes);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongDomain);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongParameters);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].Invalid);
            Assert.Equal("yes", healthCheck.CAAAnalysis.AnalysisResults[0].Parameters["cansignhttpexchanges"]);

            //  "0 issue \"letsencrypt.org;validationmethods=dns-01\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Tag == CAATagType.Issue);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Value == "letsencrypt.org;validationmethods=dns-01");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Issuer == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[1].Parameters["validationmethods"] == "dns-01");

            //  "0 issue \"pki.goog; cansignhttpexchanges=yes\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Tag == CAATagType.Issue);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Value == "pki.goog; cansignhttpexchanges=yes");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Issuer == "pki.goog");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[2].Parameters["cansignhttpexchanges"] == "yes");

            //  "0 issuewild \"letsencrypt.org\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Tag == CAATagType.IssueWildcard);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Value == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Issuer == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[3].Parameters.Count == 0);

            //  "0 issue \"letsencrypt.org\""

            //  "0 iodef \"mailto:example@example.com\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].Tag == CAATagType.Iodef);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].Value == "mailto:example@example.com");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].IsContactRecord == true);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[5].Parameters.Count == 0);

            // "260 issue \";\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Flag == "260");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Tag == CAATagType.Issue);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Value == ";");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Issuer == null);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].InvalidFlag == true);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Invalid == true);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].Parameters.Count == 0);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].DenyMailCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].DenyWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].DenyCertificateIssuance == true);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].AllowMailCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].AllowWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[6].AllowCertificateIssuance == false);

            // "0 issuemail \";\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Tag == CAATagType.IssueMail);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Value == ";");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Issuer == null);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].Parameters.Count == 0);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].DenyMailCertificateIssuance == true);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].DenyWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].DenyCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].AllowMailCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].AllowWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].AllowCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[8].IsContactRecord == false);
        }

        [Fact]
        public async Task TestCAARecordByString() {
            var caaRecord = "128 issue letsencrypt.org";
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = false;
            await healthCheck.CheckCAA(caaRecord);

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults.Count == 1);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count == 1);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[0] == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.Conflicting == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingMailIssuance == false);

            Assert.True(healthCheck.CAAAnalysis.Valid == true);
            Assert.True(healthCheck.CAAAnalysis.ReportViolationEmail.Count == 0);
            Assert.Single(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain);
            Assert.Equal("letsencrypt.org", healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain[0]);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Flag == "128");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Tag == CAATagType.Issue);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Value == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Issuer == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Invalid == false);
        }

        [Fact]
        public async Task TestCAARecordByDomain() {
            var caaRecords = new List<DnsAnswer> {
                new() { DataRaw = "0 issue \"ssl.com\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issue \"digicert.com; cansignhttpexchanges=yes\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issuewild \"comodoca.com\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issue \"pki.goog; cansignhttpexchanges=yes\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issuewild \"ssl.com\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issuewild \"letsencrypt.org\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issuewild \"pki.goog; cansignhttpexchanges=yes\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issuewild \"digicert.com; cansignhttpexchanges=yes\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issue \"comodoca.com\"", Type = DnsRecordType.CAA },
                new() { DataRaw = "0 issue \"letsencrypt.org\"", Type = DnsRecordType.CAA }
            };

            var healthCheck = new DomainHealthCheck {
                DnsConfiguration = { QueryDnsOverride = (name, type) => Task.FromResult(type == DnsRecordType.CAA ? caaRecords.ToArray() : Array.Empty<DnsAnswer>()) }
            };
            healthCheck.Verbose = false;
            await healthCheck.Verify("evotec.pl", [HealthCheckType.CAA]);

            Assert.Equal(10, healthCheck.CAAAnalysis.AnalysisResults.Count);
            Assert.Equal(5, healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count);
            Assert.Equal(5, healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count);
            Assert.False(healthCheck.CAAAnalysis.Conflicting);
            Assert.False(healthCheck.CAAAnalysis.ConflictingCertificateIssuance);
            Assert.False(healthCheck.CAAAnalysis.ConflictingWildcardCertificateIssuance);
            Assert.False(healthCheck.CAAAnalysis.ConflictingMailIssuance);
            Assert.True(healthCheck.CAAAnalysis.Valid);
            Assert.Empty(healthCheck.CAAAnalysis.CanIssueMail);
            Assert.False(healthCheck.CAAAnalysis.HasDuplicateIssuers);
        }

        [Fact]
        public async Task CaseInsensitiveTagParsing() {
            var caaRecord = "0 ISSUE \"letsencrypt.org\"";
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = false;
            await healthCheck.CheckCAA(caaRecord);

            Assert.Single(healthCheck.CAAAnalysis.AnalysisResults);
            Assert.Equal(CAATagType.Issue, healthCheck.CAAAnalysis.AnalysisResults[0].Tag);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag);
            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidFlag);
        }

        [Fact]
        public async Task CriticalBitIsDetected() {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA("128 issue \"letsencrypt.org\"");

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Critical);
        }

        [Fact]
        public async Task UnknownCriticalPropertyTagTriggersWarning() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);

            await healthCheck.CheckCAA("128 foo \"bar\"");

            Assert.Contains(warnings, w => w.FullMessage.Contains("Unknown CAA property tag"));
        }

        [Fact]
        public async Task UnknownCriticalTagFailsCheck() {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA("128 foo \"bar\"");

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag);
            Assert.False(healthCheck.CAAAnalysis.Valid);
        }

        [Fact]
        public async Task UnknownNonCriticalTagIsIgnored() {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA("0 foo \"bar\"");

            Assert.False(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag);
            Assert.True(healthCheck.CAAAnalysis.Valid);
        }

        [Fact]
        public async Task ReservedFlagBitsTriggerWarning() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var healthCheck = new DomainHealthCheck(internalLogger: logger);

            await healthCheck.CheckCAA("129 issue \"letsencrypt.org\"");

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidFlag);
            Assert.Contains(warnings, w => w.FullMessage.Contains("reserved flag bits"));
        }

        [Fact]
        public async Task EmptyAndNonEmptyIssuePropertiesAreAdditiveNotConflicting() {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA(new List<string> {
                "0 issue \";\"",
                "0 issue \"letsencrypt.org\""
            });

            Assert.False(healthCheck.CAAAnalysis.Conflicting);
            Assert.True(healthCheck.CAAAnalysis.Valid);
            Assert.Equal(new[] { "letsencrypt.org" }, healthCheck.CAAAnalysis.CanIssueCertificatesForDomain);
        }

        [Fact]
        public async Task EmptyIssuerWithoutSemicolonDeniesIssuance() {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA("0 issue \"\"");

            var result = Assert.Single(healthCheck.CAAAnalysis.AnalysisResults);
            Assert.True(result.DenyCertificateIssuance);
            Assert.False(result.AllowCertificateIssuance);
            Assert.Null(result.Issuer);
            Assert.False(result.Invalid);
        }

        [Theory]
        [InlineData("0 issue \"https://ca.example\"")]
        [InlineData("0 issue \"-ca.example\"")]
        [InlineData("0 issue \"ca..example\"")]
        public async Task InvalidIssuerDomainIsRejected(string record) {
            var healthCheck = new DomainHealthCheck();

            await healthCheck.CheckCAA(record);

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongDomain);
            Assert.False(healthCheck.CAAAnalysis.Valid);
        }

        [Fact]
        public async Task VerifyCaaUsesFirstParentRrset() {
            var queries = new List<string>();
            var healthCheck = new DomainHealthCheck {
                DnsConfiguration = {
                    QueryDnsOverride = (name, type) => {
                        queries.Add(name);
                        if (type == DnsRecordType.CAA && name == "example.com") {
                            return Task.FromResult(new[] {
                                new DnsAnswer { Name = name, Type = type, DataRaw = "0 issue \"letsencrypt.org\"" }
                            });
                        }
                        return Task.FromResult(Array.Empty<DnsAnswer>());
                    }
                }
            };

            await healthCheck.VerifyCAA("www.mail.example.com");

            Assert.Equal(new[] { "www.mail.example.com", "mail.example.com", "example.com" }, queries);
            Assert.Equal("example.com", healthCheck.CAAAnalysis.DomainName);
            Assert.True(healthCheck.CAAAnalysis.PolicyInherited);
            Assert.Equal(new[] { "letsencrypt.org" }, healthCheck.CAAAnalysis.CanIssueCertificatesForDomain);
        }
    }
}
