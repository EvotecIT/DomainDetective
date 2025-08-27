using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SmimeaRecordInfo Convert(SMIMEAAnalysis analysis)
    {
        var recs = RecommendationEngine.From(analysis.Assessments);
        var valid = analysis.AnalysisResults?.Count(r => r.ValidSMIMEARecord) ?? 0;
        var total = analysis.AnalysisResults?.Count ?? 0;
        return new SmimeaRecordInfo
        {
            NumberOfRecords = total,
            ValidRecords = valid,
            HasInvalidRecords = total > 0 && valid < total,
            Assessments = analysis.Assessments,
            Recommendations = recs,
            References = new[] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Raw = analysis
        };
    }
}

public class SmimeaRecordInfo
{
    public int NumberOfRecords { get; set; }
    public int ValidRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SMIMEAAnalysis Raw { get; set; }
}

