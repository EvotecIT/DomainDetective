using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides smimea record info functionality.</summary>
public class SmimeaRecordInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the number of records value.</summary>
    public int NumberOfRecords { get; set; }
    /// <summary>Gets or sets the valid records value.</summary>
    public int ValidRecords { get; set; }
    /// <summary>Gets or sets the has invalid records value.</summary>
    public bool HasInvalidRecords { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public SMIMEAAnalysis Raw { get; set; } = null!;
}
