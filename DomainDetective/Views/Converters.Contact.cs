using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ContactInfo Convert(ContactInfoAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warn, out var err, out var status);
        return new ContactInfo
        {
            Check = HealthCheckType.CONTACT,
            Area = AreaForKind(HealthCheckType.CONTACT),
            Subject = analysis.Subject ?? string.Empty,
            RecordExists = analysis.RecordExists,
            ContactRecord = analysis.ContactRecord ?? string.Empty,
            Fields = analysis.Fields,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = analysis.RecordExists ? "present" : "missing",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing Contact TXT record analysis.
/// </summary>
public class ContactInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    public bool RecordExists { get; set; }
    /// <summary>Raw contact TXT record.</summary>
    public string ContactRecord { get; set; } = string.Empty;
    /// <summary>Key-value fields parsed from the contact record.</summary>
    public IReadOnlyDictionary<string, string> Fields { get; set; } = new System.Collections.Generic.Dictionary<string, string>();
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    /// <summary>Short summary text used in executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public ContactInfoAnalysis Raw { get; set; } = new ContactInfoAnalysis();
}
