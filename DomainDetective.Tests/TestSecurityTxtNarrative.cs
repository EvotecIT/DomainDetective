using System.Linq;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestSecurityTxtNarrative {
    [Fact]
    public void BuildsNarrativeAndPositiveAdvice() {
        var analysis = new SecurityTXTAnalysis {
            Domain = "example.com",
            RecordPresent = true,
            RecordValid = true
        };

        analysis.ContactEmail.Add("admin@example.com");
        analysis.Encryption.Add("https://example.com/pgp.txt");
        analysis.Policy.Add("https://example.com/policy");

        analysis.Assessments.Add(new Assessment {
            Code = SecurityTxtCodes.RecordPresent,
            Severity = AssessmentSeverity.Info,
            Message = "security.txt present"
        });
        analysis.Assessments.Add(new Assessment {
            Code = SecurityTxtCodes.RecordValid,
            Severity = AssessmentSeverity.Info,
            Message = "security.txt syntax valid"
        });

        var sections = SecurityTxtNarrative.Build(analysis);
        Assert.Contains("admin@example.com", string.Join(" ", sections.Highlights));
        Assert.Contains("pgp.txt", string.Join(" ", sections.Highlights));
        Assert.Contains("policy", string.Join(" ", sections.Highlights));

        var codes = analysis.Recommendations.Select(r => r.Code).ToList();
        Assert.Contains(SecurityTxtCodes.RecordPresent, codes);
        Assert.Contains(SecurityTxtCodes.RecordValid, codes);
    }
}

