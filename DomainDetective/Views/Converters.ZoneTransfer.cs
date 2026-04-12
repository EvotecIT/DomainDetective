using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static ZoneTransferInfo Convert(ZoneTransferAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var serverResults = analysis.ServerResults ?? new Dictionary<string, bool>();
        var total = serverResults.Count;
        var open = serverResults.Count(kv => kv.Value);
        return new ZoneTransferInfo
        {
            Check = HealthCheckType.ZONETRANSFER,
            Area = AreaForKind(HealthCheckType.ZONETRANSFER),
            Subject = analysis.Subject ?? string.Empty,
            TotalChecked = total,
            OpenCount = open,
            ServerResults = serverResults,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open {open}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides zone transfer info functionality.</summary>
public class ZoneTransferInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the open count value.</summary>
    public int OpenCount { get; set; }
    /// <summary>Gets or sets the server results value.</summary>
    public IReadOnlyDictionary<string, bool> ServerResults { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public ZoneTransferAnalysis Raw { get; set; } = new ZoneTransferAnalysis();
}
