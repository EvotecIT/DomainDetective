using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static FcrDnsInfo Convert(FCrDnsAnalysis analysis)
    {
        // FCrDnsAnalysis does not expose assessments; derive a simple status
        var assessments = new List<Assessment>();
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.ForwardConfirmed) ?? 0;
        string status = total == valid ? "OK" : (valid > 0 ? "Warning" : "Error");
        int warn = (total > valid && valid > 0) ? 1 : 0;
        int err = (valid == 0 && total > 0) ? 1 : 0;
        return new FcrDnsInfo
        {
            Check = HealthCheckType.FCRDNS,
            Area = AreaForKind(HealthCheckType.FCRDNS),
            Subject = analysis.Subject,
            TotalChecked = total,
            ForwardConfirmed = valid,
            Results = analysis.Results,
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = $"{valid}/{total} forward-confirmed",
            Recommendations = RecommendationEngine.From(assessments),
            References = BuildReferences(System.Array.Empty<StandardReference>(), RecommendationEngine.From(assessments)),
            Raw = analysis
        };
    }
}

public class FcrDnsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int ForwardConfirmed { get; set; }
    public IReadOnlyList<FCrDnsAnalysis.FCrDnsResult> Results { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public FCrDnsAnalysis Raw { get; set; }
}
