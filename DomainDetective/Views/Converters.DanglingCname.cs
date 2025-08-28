namespace DomainDetective.Views;

public static partial class Converters
{
    public static DanglingCnameInfo Convert(DanglingCnameAnalysis analysis)
    {
        var assessments = analysis.Assessments;
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new DanglingCnameInfo
        {
            Check = "DANGLINGCNAME",
            Subject = null,
            CnameRecordExists = analysis.CnameRecordExists,
            Target = analysis.Target,
            TargetResolves = analysis.TargetResolves,
            KnownService = analysis.KnownService,
            IsDangling = analysis.IsDangling,
            UnclaimedService = analysis.UnclaimedService,
            FailureReason = analysis.FailureReason,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class DanglingCnameInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public bool CnameRecordExists { get; set; }
    public string Target { get; set; }
    public bool TargetResolves { get; set; }
    public bool KnownService { get; set; }
    public bool IsDangling { get; set; }
    public bool UnclaimedService { get; set; }
    public string FailureReason { get; set; }
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; }
    public DanglingCnameAnalysis Raw { get; set; }
}

