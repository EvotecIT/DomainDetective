using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static IpEnrichmentInfo Convert(IpEnrichmentAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        return new IpEnrichmentInfo
        {
            Check = HealthCheckType.IPENRICHMENT,
            Area = AreaForKind(HealthCheckType.IPENRICHMENT),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            ResultsCapped = analysis.ResultsCapped,
            FailureReason = analysis.FailureReason,
            UniqueIpCount = analysis.UniqueIpCount,
            RowCount = analysis.RowCount,
            DistinctAsnCount = analysis.DistinctAsnCount,
            DistinctCountryCount = analysis.DistinctCountryCount,
            AsnCounts = analysis.AsnCounts,
            CountryCounts = analysis.CountryCounts,
            Rows = analysis.Rows,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"IPs {analysis.UniqueIpCount}; rows {analysis.RowCount}; ASNs {analysis.DistinctAsnCount}; countries {analysis.DistinctCountryCount}; capped {(analysis.ResultsCapped ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.References, recs),
            Raw = analysis
        };
    }
}

public sealed class IpEnrichmentInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool QuerySucceeded { get; set; }
    public bool ResultsCapped { get; set; }
    public string? FailureReason { get; set; }
    public int UniqueIpCount { get; set; }
    public int RowCount { get; set; }
    public int DistinctAsnCount { get; set; }
    public int DistinctCountryCount { get; set; }
    public IReadOnlyDictionary<int, int> AsnCounts { get; set; } = null!;
    public IReadOnlyDictionary<string, int> CountryCounts { get; set; } = null!;
    public IReadOnlyList<IpEnrichmentRow> Rows { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public IpEnrichmentAnalysis Raw { get; set; } = null!;
}

