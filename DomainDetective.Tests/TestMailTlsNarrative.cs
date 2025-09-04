using DomainDetective.Narratives;
using System.Security.Authentication;
using Xunit;
using DomainDetective;

namespace DomainDetective.Tests
{
    public class TestMailTlsNarrative
    {
        [Fact]
        public void BuildsNarrativeWithPositives()
        {
            var analysis = new MailTlsAnalysis { Subject = "example.com" };
            analysis.ServerResults["smtp.example.com:587"] = new MailTlsAnalysis.TlsResult
            {
                Protocol = SslProtocols.Tls12,
                CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                CertificateValid = true,
                HostnameMatch = true,
                ChainErrors = { },
                IsExpired = false,
                DaysToExpire = 90
            };
            analysis.Assessments.Add(new Assessment { Code = MailTlsCodes.StrongCipherSuite, Severity = AssessmentSeverity.Info, Message = "Strong cipher" });
            analysis.Assessments.Add(new Assessment { Code = MailTlsCodes.CertificateValid, Severity = AssessmentSeverity.Info, Message = "Valid certificate" });

            var sections = MailTlsNarrative.Build(analysis, MailTlsAnalysis.MailProtocol.Smtp);
            Assert.Contains(sections.Highlights, h => h.Contains("TLS"));
            Assert.Contains("Strong cipher suite negotiated", sections.Positives);
            Assert.Contains("Valid TLS certificate", sections.Positives);
        }
    }
}
