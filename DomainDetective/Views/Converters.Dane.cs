using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DaneRecordInfo Convert(DANEAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        return new DaneRecordInfo
        {
            Check = HealthCheckType.DANE,
            Area = AreaForKind(HealthCheckType.DANE),
            Subject = analysis.Subject ?? string.Empty,
            NumberOfRecords = analysis.NumberOfRecords,
            HasDuplicateRecords = analysis.HasDuplicateRecords,
            HasInvalidRecords = analysis.HasInvalidRecords,
            QueriedNames = analysis.QueriedNames,
            QueriedPorts = analysis.QueriedPorts,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.NumberOfRecords} records; invalid {(analysis.HasInvalidRecords ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing DANE (TLSA) record analysis.
/// </summary>
public class DaneRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public int NumberOfRecords { get; set; }
    public bool HasDuplicateRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<string> QueriedNames { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<int> QueriedPorts { get; set; } = System.Array.Empty<int>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DANEAnalysis Raw { get; set; } = new DANEAnalysis();
}
