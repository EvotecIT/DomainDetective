using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SmimeaRecordInfo Convert(SMIMEAAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var valid = analysis.AnalysisResults?.Count(r => r.ValidSMIMEARecord) ?? 0;
        var total = analysis.AnalysisResults?.Count ?? 0;
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        return new SmimeaRecordInfo
        {
            Check = HealthCheckType.SMIMEA,
            Area = AreaForKind(HealthCheckType.SMIMEA),
            Subject = analysis.Subject,
            NumberOfRecords = total,
            ValidRecords = valid,
            HasInvalidRecords = total > 0 && valid < total,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"valid {valid}/{total}",
            Recommendations = recs,
            Positives = positives,
            References = new[] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Raw = analysis
        };
    }
}

public class SmimeaRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int NumberOfRecords { get; set; }
    public int ValidRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public SMIMEAAnalysis Raw { get; set; } = null!;
}
