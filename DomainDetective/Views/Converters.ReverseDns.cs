using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ReverseDnsInfo Convert(ReverseDnsAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.IsValid) ?? 0;
        return new ReverseDnsInfo
        {
            Check = "RDNS",
            Area = AreaFor("RDNS"),
            Subject = analysis.Subject,
            ResultsCount = total,
            ValidCount = valid,
            AllValid = analysis.AllValid,
            Results = analysis.Results,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{valid}/{total} PTR match; FCrDNS {(analysis.Results?.Count(r => r.FcrDnsValid) ?? 0)}/{total}",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

public class ReverseDnsInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public int ResultsCount { get; set; }
    public int ValidCount { get; set; }
    public bool AllValid { get; set; }
    public IReadOnlyList<ReverseDnsAnalysis.ReverseDnsResult> Results { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ReverseDnsAnalysis Raw { get; set; }
}
