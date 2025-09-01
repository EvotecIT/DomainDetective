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
            References = new[] { "https://www.rfc-editor.org/rfc/rfc8162" },
            Raw = analysis
        };
    }
}

public class SmimeaRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int NumberOfRecords { get; set; }
    public int ValidRecords { get; set; }
    public bool HasInvalidRecords { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SMIMEAAnalysis Raw { get; set; }
}
