using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MtastsInfo Convert(MTASTSAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new MtastsInfo
        {
            Check = HealthCheckType.MTASTS,
            Area = AreaForKind(HealthCheckType.MTASTS),
            Subject = analysis.Domain,
            DnsRecordPresent = analysis.DnsRecordPresent,
            DnsRecordValid = analysis.DnsRecordValid,
            PolicyPresent = analysis.PolicyPresent,
            PolicyValid = analysis.PolicyValid,
            Mode = analysis.Mode,
            MaxAge = analysis.MaxAge,
            HasMx = analysis.HasMx,
            MxAligned = analysis.MxAligned,
            MissingMxFromPolicy = analysis.MissingMxFromPolicy?.ToArray() ?? System.Array.Empty<string>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"mode {(analysis.Mode ?? "?")}; max-age {analysis.MaxAge}; DNS {(analysis.DnsRecordPresent ? "yes" : "no")}; valid {(analysis.PolicyValid ? "yes" : "no")}; MX aligned {(analysis.MxAligned ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class MtastsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public bool DnsRecordPresent { get; set; }
    public bool DnsRecordValid { get; set; }
    public bool PolicyPresent { get; set; }
    public bool PolicyValid { get; set; }
    public string Mode { get; set; } = null!;
    public int MaxAge { get; set; }
    public bool HasMx { get; set; }
    public bool MxAligned { get; set; }
    public string[] MissingMxFromPolicy { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public MTASTSAnalysis Raw { get; set; } = null!;
}

