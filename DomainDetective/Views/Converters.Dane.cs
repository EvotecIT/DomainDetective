using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DaneRecordInfo Convert(DANEAnalysis analysis)
    {
        var recs = RecommendationEngine.From(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        return new DaneRecordInfo
        {
            Check = HealthCheckType.DANE,
            Area = AreaForKind(HealthCheckType.DANE),
            Subject = analysis.Subject,
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
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class DaneRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int NumberOfRecords { get; set; }
    public bool HasDuplicateRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<string> QueriedNames { get; set; }
    public IReadOnlyList<int> QueriedPorts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DANEAnalysis Raw { get; set; }
}
