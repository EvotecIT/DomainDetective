using System.Collections.Generic;
using System.Reflection;
using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestDnssecNarrative
{
    [Fact]
    public void BuildsNarrativeWithHighlightsAndPositives()
    {
        var analysis = new DnsSecAnalysis();
        Set(analysis, nameof(DnsSecAnalysis.DsRecords), new List<string> {
            "2371 13 2 C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A"
        });
        Set(analysis, nameof(DnsSecAnalysis.DnsKeys), new List<string> { "257 3 13 AQID" });
        Set(analysis, nameof(DnsSecAnalysis.ChainValid), true);
        Set(analysis, nameof(DnsSecAnalysis.DsMatch), true);
        Set(analysis, nameof(DnsSecAnalysis.AuthenticData), true);
        Set(analysis, nameof(DnsSecAnalysis.ValidationStatus), DnssecValidationStatus.Secure);
        analysis.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Info,
            Category = "DNSSEC",
            Code = DnssecCodes.ChainValid,
            Target = "example.com",
            Message = "DnsClientX locally authenticated the DNSSEC chain."
        });

        var sections = DnssecNarrative.Build(analysis, analysis.Assessments);
        Assert.Contains(sections.Highlights, h => h.Contains("DS record"));
        Assert.Contains(sections.Highlights, h => h.Contains("Key algorithms"));
        Assert.Contains(sections.Highlights, h => h.Contains("authenticated", System.StringComparison.OrdinalIgnoreCase));
        Assert.NotEmpty(sections.Positives);
    }

    private static void Set<T>(DnsSecAnalysis analysis, string property, T value) {
        typeof(DnsSecAnalysis).GetProperty(property, BindingFlags.Instance | BindingFlags.Public)!.SetValue(analysis, value);
    }
}
