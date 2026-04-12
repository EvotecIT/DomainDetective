namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the cname record exists value.</summary>
    public bool CnameRecordExists { get; set; }
    /// <summary>Gets or sets the target value.</summary>
    public string Target { get; set; } = string.Empty;
    /// <summary>Gets or sets the target resolves value.</summary>
    public bool TargetResolves { get; set; }
    /// <summary>Gets or sets the known service value.</summary>
    public bool KnownService { get; set; }
    /// <summary>Gets or sets the is dangling value.</summary>
    public bool IsDangling { get; set; }
    /// <summary>Gets or sets the unclaimed service value.</summary>
    public bool UnclaimedService { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string FailureReason { get; set; } = string.Empty;
    /// <summary>Gets or sets the assessments value.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public DanglingCnameAnalysis Raw { get; set; } = new DanglingCnameAnalysis();
}
