using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsTunnelingInfo Convert(DnsTunnelingAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new DnsTunnelingInfo
        {
            Check = "DNSTUNNELING",
            Subject = null,
            Alerts = analysis.Alerts,
            AlertCount = analysis.Alerts?.Count ?? 0,
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

public class DnsTunnelingInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int AlertCount { get; set; }
    public IReadOnlyList<DnsTunnelingAlert> Alerts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DnsTunnelingAnalysis Raw { get; set; }
}

