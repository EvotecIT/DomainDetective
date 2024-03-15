using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestCAAAnalysis {
        [Fact]
        public async void TestCAARecordByList() {
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
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = false;
            await healthCheck.CheckCAA(caaRecords);

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults.Count == 9);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count == 5);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[0] == "digicert.com");
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[1] == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[2] == "pki.goog");
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[3] == "letsencrypt.org");
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain[4] == "letsencrypt.org");

            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count == 1);
            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain[0] == "letsencrypt.org");

            //  "0 issue \"digicert.com; cansignhttpexchanges=yes\""
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Flag == "0");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Tag == CAATagType.Issue);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Value == "digicert.com; cansignhttpexchanges=yes");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Issuer == "digicert.com");
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidFlag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidTag == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueUnescapedQuotes == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongDomain == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].InvalidValueWrongParameters == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Invalid == false);
            Assert.True(healthCheck.CAAAnalysis.AnalysisResults[0].Parameters["cansignhttpexchanges"] == "yes");

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
        public async void TestCAARecordByString() {
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
            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count == 0);

            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count == 0);
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
        public async void TestCAARecordByDomain() {
            var healthCheck = new DomainHealthCheck();
            healthCheck.Verbose = false;
            await healthCheck.Verify("evotec.pl", new[] { HealthCheckType.CAA });

            Assert.True(healthCheck.CAAAnalysis.AnalysisResults.Count == 8);
            Assert.True(healthCheck.CAAAnalysis.CanIssueCertificatesForDomain.Count == 4);
            Assert.True(healthCheck.CAAAnalysis.CanIssueWildcardCertificatesForDomain.Count == 4);
            Assert.True(healthCheck.CAAAnalysis.Conflicting == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingWildcardCertificateIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.ConflictingMailIssuance == false);
            Assert.True(healthCheck.CAAAnalysis.Valid == true);
            Assert.True(healthCheck.CAAAnalysis.CanIssueMail.Count == 0);
        }
    }
}
