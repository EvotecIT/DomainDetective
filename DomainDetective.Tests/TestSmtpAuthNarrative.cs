using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests
{
    public class TestSmtpAuthNarrative
    {
        [Fact]
        public void NarrativeSummarizesMechanismsAndTls()
        {
            var analysis = new SmtpAuthAnalysis { Subject = "example.com", InspectCapabilities = true };
            analysis.ServerMechanisms["smtp.example.com:587"] = new[] { "LOGIN", "PLAIN" };
            analysis.ServerCapabilities["smtp.example.com:587"] = new[] { "AUTH", "STARTTLS" };
            analysis.Assessments.Add(new Assessment { Code = SmtpAuthCodes.TlsRequired, Severity = AssessmentSeverity.Info, Message = "TLS required" });
            var sections = SmtpAuthNarrative.Build(analysis);
            Assert.Contains("smtp.example.com:587 supports LOGIN PLAIN", sections.Highlights);
            Assert.Contains("smtp.example.com:587 advertises STARTTLS.", sections.Highlights);
            Assert.Contains("AUTH protected by TLS", sections.Positives);
        }
    }
}
