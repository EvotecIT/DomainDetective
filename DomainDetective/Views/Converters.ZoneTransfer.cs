using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ZoneTransferInfo Convert(ZoneTransferAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        var total = analysis.ServerResults?.Count ?? 0;
        var open = analysis.ServerResults?.Count(kv => kv.Value) ?? 0;
        return new ZoneTransferInfo
        {
            Check = "AXFR",
            Subject = null,
            TotalChecked = total,
            OpenCount = open,
            ServerResults = analysis.ServerResults,
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

public class ZoneTransferInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenCount { get; set; }
    public IReadOnlyDictionary<string, bool> ServerResults { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ZoneTransferAnalysis Raw { get; set; }
}

