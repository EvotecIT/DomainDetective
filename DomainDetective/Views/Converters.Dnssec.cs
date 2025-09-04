using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnssecStatusInfo Convert(DnsSecAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new DnssecStatusInfo
        {
            Check = HealthCheckType.DNSSEC,
            Area = AreaForKind(HealthCheckType.DNSSEC),
            Subject = analysis.Subject,
            AuthenticData = analysis.AuthenticData,
            DsAuthenticData = analysis.DsAuthenticData,
            DsMatch = analysis.DsMatch,
            ChainValid = analysis.ChainValid,
            RootAnchorExpiration = analysis.RootAnchorExpiration,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"chain {(analysis.ChainValid ? "valid" : "invalid")}; DS {(analysis.DsMatch ? "match" : "check")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4035" },
            Raw = analysis
        };
    }
}

public class DnssecStatusInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public bool AuthenticData { get; set; }
    public bool DsAuthenticData { get; set; }
    public bool DsMatch { get; set; }
    public bool ChainValid { get; set; }
    public System.DateTimeOffset? RootAnchorExpiration { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DnsSecAnalysis Raw { get; set; }
}
