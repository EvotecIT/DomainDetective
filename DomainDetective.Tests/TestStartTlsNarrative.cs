using DomainDetective.Narratives;
using Xunit;
using DomainDetective;

namespace DomainDetective.Tests;

public class TestStartTlsNarrative
{
    [Fact]
    public void BuildsNarrativeWithPositives()
    {
        var analysis = new STARTTLSAnalysis { Subject = "example.com" };
        analysis.ServerDetails["smtp.example.com:25"] = new STARTTLSResult
        {
            Host = "smtp.example.com",
            Port = 25,
            StartTlsAdvertised = true,
            TlsNegotiated = true,
            TlsProtocol = "TLS1.2",
            CipherAlgorithm = "AES",
            CipherStrength = 256
        };
        analysis.Assessments.Add(new Assessment { Code = StartTlsCodes.Enforced, Severity = AssessmentSeverity.Info, Message = "Enforced" });
        analysis.Assessments.Add(new Assessment { Code = StartTlsCodes.ModernCipher, Severity = AssessmentSeverity.Info, Message = "Modern" });

        var sections = StartTlsNarrative.Build(analysis);

        Assert.Contains(sections.Highlights, h => h.Contains("advertises STARTTLS"));
        Assert.Contains("STARTTLS enforced", sections.Positives);
        Assert.Contains("Modern cipher suite negotiated", sections.Positives);
    }
}
