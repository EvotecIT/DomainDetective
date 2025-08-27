using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DaneRecordInfo Convert(DANEAnalysis analysis)
    {
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new DaneRecordInfo
        {
            NumberOfRecords = analysis.NumberOfRecords,
            HasDuplicateRecords = analysis.HasDuplicateRecords,
            HasInvalidRecords = analysis.HasInvalidRecords,
            QueriedNames = analysis.QueriedNames,
            QueriedPorts = analysis.QueriedPorts,
            Assessments = analysis.Assessments,
            Recommendations = recs,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class DaneRecordInfo
{
    public int NumberOfRecords { get; set; }
    public bool HasDuplicateRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<string> QueriedNames { get; set; }
    public IReadOnlyList<int> QueriedPorts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DANEAnalysis Raw { get; set; }
}

