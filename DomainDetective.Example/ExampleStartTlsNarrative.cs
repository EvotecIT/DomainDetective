using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program
{
    /// <summary>
    /// Demonstrates building a STARTTLS narrative.
    /// </summary>
    public static Task ExampleStartTlsNarrative()
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
        analysis.Assessments.Add(new Assessment { Code = "STARTTLS.Session.Enforced", Severity = AssessmentSeverity.Info });
        analysis.Assessments.Add(new Assessment { Code = "STARTTLS.Cipher.Modern", Severity = AssessmentSeverity.Info });
        var narrative = StartTlsNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("STARTTLS Narrative", narrative);
        return Task.CompletedTask;
    }
}
