namespace DomainDetective.Views;

public static partial class Converters
{
    public static DanglingCnameInfo Convert(DanglingCnameAnalysis analysis)
    {
        var assessments = analysis.Assessments;
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new DanglingCnameInfo
        {
            Check = HealthCheckType.DANGLINGCNAME,
            Area = AreaForKind(HealthCheckType.DANGLINGCNAME),
            Subject = analysis.Subject ?? string.Empty,
            CnameRecordExists = analysis.CnameRecordExists,
            Target = analysis.Target ?? string.Empty,
            TargetResolves = analysis.TargetResolves,
            KnownService = analysis.KnownService,
            IsDangling = analysis.IsDangling,
            UnclaimedService = analysis.UnclaimedService,
            FailureReason = analysis.FailureReason ?? string.Empty,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"dangling {(analysis.IsDangling ? "yes" : "no")}; service {(analysis.KnownService ? "known" : "unknown")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing dangling CNAME analysis (takeover risk).
/// </summary>
public class DanglingCnameInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public bool CnameRecordExists { get; set; }
    public string Target { get; set; } = string.Empty;
    public bool TargetResolves { get; set; }
    public bool KnownService { get; set; }
    public bool IsDangling { get; set; }
    public bool UnclaimedService { get; set; }
    public string FailureReason { get; set; } = string.Empty;
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DanglingCnameAnalysis Raw { get; set; } = new DanglingCnameAnalysis();
}
