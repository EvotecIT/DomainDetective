using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ReverseDnsInfo Convert(ReverseDnsAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var total = analysis.Results?.Count ?? 0;
        var valid = analysis.Results?.Count(r => r.IsValid) ?? 0;
        return new ReverseDnsInfo
        {
            Check = HealthCheckType.REVERSEDNS,
            Area = AreaForKind(HealthCheckType.REVERSEDNS),
            Subject = analysis.Subject,
            ResultsCount = total,
            ValidCount = valid,
            AllValid = analysis.AllValid,
            Results = analysis.Results ?? new List<ReverseDnsAnalysis.ReverseDnsResult>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{valid}/{total} PTR match; FCrDNS {(analysis.Results?.Count(r => r.FcrDnsValid) ?? 0)}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

public class ReverseDnsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int ResultsCount { get; set; }
    public int ValidCount { get; set; }
    public bool AllValid { get; set; }
    public IReadOnlyList<ReverseDnsAnalysis.ReverseDnsResult> Results { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public ReverseDnsAnalysis Raw { get; set; } = null!;
}
