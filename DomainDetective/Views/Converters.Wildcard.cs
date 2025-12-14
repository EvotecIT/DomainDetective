using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static WildcardDnsInfo Convert(WildcardDnsAnalysis analysis)
    {
        var assessments = (analysis as IHasAssessments)?.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new WildcardDnsInfo
        {
            Check = HealthCheckType.WILDCARDDNS,
            Area = AreaForKind(HealthCheckType.WILDCARDDNS),
            Subject = string.Empty,
            CatchAll = analysis.CatchAll,
            SoaExists = analysis.SoaExists,
            NsExists = analysis.NsExists,
            TestedNames = analysis.TestedNames,
            ResolvedNames = analysis.ResolvedNames,
            ResolvedAddresses = analysis.ResolvedAddresses,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = analysis.CatchAll ? "enabled" : "disabled",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4592" },
            Raw = analysis
        };
    }
}

public class WildcardDnsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public bool CatchAll { get; set; }
    public bool SoaExists { get; set; }
    public bool NsExists { get; set; }
    public IReadOnlyList<string> TestedNames { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> ResolvedNames { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> ResolvedAddresses { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public WildcardDnsAnalysis Raw { get; set; } = new WildcardDnsAnalysis();
}
