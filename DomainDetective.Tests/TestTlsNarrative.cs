using DomainDetective.Narratives;
using System.Security.Authentication;
using Xunit;

namespace DomainDetective.Tests;

public class TestTlsNarrative
{
    [Fact]
    public void BuildsNarrativeWithPositives()
    {
        var analysis = new TlsAnalysis { Subject = "example.com" };
        analysis.ServerResults["www.example.com:443"] = new TlsProbe.Result
        {
            Protocol = SslProtocols.Tls13,
            CipherSuite = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            CertificateValid = true,
            HostnameMatch = true
        };
        analysis.Assessments.Add(new Assessment { Code = TlsCodes.StrongProtocol, Severity = AssessmentSeverity.Info, Message = "Strong protocol" });
        analysis.Assessments.Add(new Assessment { Code = TlsCodes.PfsCipher, Severity = AssessmentSeverity.Info, Message = "Forward secrecy" });

        var sections = TlsNarrative.Build(analysis);
        Assert.Contains(sections.Highlights, h => h.Contains("TLS"));
        Assert.Contains("Modern TLS protocol negotiated", sections.Positives);
        Assert.Contains("Forward secrecy cipher suite negotiated", sections.Positives);
    }
}

