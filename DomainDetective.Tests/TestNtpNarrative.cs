using DomainDetective;
using DomainDetective.Narratives;
using Xunit;

namespace DomainDetective.Tests;

public class TestNtpNarrative {
    [Fact]
    public void BuildsNarrativeWithPositives() {
        var analysis = new NtpAnalysis();
        analysis.ServerResults["time.example:123"] = new NtpAnalysis.NtpResult {
            Success = true,
            Offset = System.TimeSpan.FromMilliseconds(20),
            Stratum = 2
        };
        analysis.Assessments.Add(new Assessment { Code = NtpCodes.ReasonableOffset, Severity = AssessmentSeverity.Info, Message = "Offset ok" });
        analysis.Assessments.Add(new Assessment { Code = NtpCodes.TrustedStratum, Severity = AssessmentSeverity.Info, Message = "Stratum ok" });

        var sections = NtpNarrative.Build(analysis);

        Assert.Contains(sections.Highlights, h => h.Contains("stratum 2"));
        Assert.Contains("Clock offset within acceptable range", sections.Positives);
        Assert.Contains("NTP server reports trusted stratum", sections.Positives);
    }

    [Fact]
    public void FormatsLargeOffsetsInLargerUnits() {
        var analysis = new NtpAnalysis();
        analysis.ServerResults["time.example:123"] = new NtpAnalysis.NtpResult {
            Success = true,
            Offset = System.TimeSpan.FromSeconds(2),
            Stratum = 1
        };

        var sections = NtpNarrative.Build(analysis);

        Assert.Contains(sections.Highlights, h => h.Contains("2.00 s"));
    }
}

