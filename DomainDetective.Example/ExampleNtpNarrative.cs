using System;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Narratives;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>Demonstrates building an NTP narrative.</summary>
    public static Task ExampleNtpNarrative() {
        var analysis = new NtpAnalysis();
        analysis.ServerResults["pool.ntp.org:123"] = new NtpAnalysis.NtpResult {
            Success = true,
            Offset = TimeSpan.FromMilliseconds(15),
            Stratum = 2
        };
        analysis.Assessments.Add(new Assessment { Code = "NTP.Offset.Reasonable", Severity = AssessmentSeverity.Info });
        analysis.Assessments.Add(new Assessment { Code = "NTP.Stratum.Trusted", Severity = AssessmentSeverity.Info });
        var narrative = NtpNarrative.Build(analysis);
        Helpers.ShowPropertiesTable("NTP Narrative", narrative);
        return Task.CompletedTask;
    }
}

