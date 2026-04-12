using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static SoaInfo Convert(SOAAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new SoaInfo
        {
            Check = HealthCheckType.SOA,
            Area = AreaForKind(HealthCheckType.SOA),
            Subject = analysis.Subject ?? analysis.DomainName ?? string.Empty,
            PrimaryNameServer = analysis.PrimaryNameServer ?? string.Empty,
            ResponsibleMailbox = analysis.ResponsibleMailbox ?? string.Empty,
            SerialNumber = analysis.SerialNumber,
            SerialFormatValid = analysis.SerialFormatValid,
            SerialFormatSuggestion = analysis.SerialFormatSuggestion ?? string.Empty,
            Refresh = analysis.Refresh,
            Retry = analysis.Retry,
            Expire = analysis.Expire,
            Minimum = analysis.Minimum,
            NegativeCacheTtl = analysis.NegativeCacheTtl,
            RecordExists = analysis.RecordExists,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"serial {analysis.SerialNumber} ({(analysis.SerialFormatValid ? "valid" : "check")}); refresh {analysis.Refresh}s",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing SOA (Start of Authority) analysis.
/// </summary>
public class SoaInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Primary name server (MNAME).</summary>
    public string PrimaryNameServer { get; set; } = string.Empty;
    /// <summary>Responsible mailbox (RNAME).</summary>
    public string ResponsibleMailbox { get; set; } = string.Empty;
    /// <summary>Gets or sets the serial number value.</summary>
    public long SerialNumber { get; set; }
    /// <summary>Gets or sets the serial format valid value.</summary>
    public bool SerialFormatValid { get; set; }
    /// <summary>Suggestion when the serial format is not YYYMMDDnn.</summary>
    public string SerialFormatSuggestion { get; set; } = string.Empty;
    /// <summary>Gets or sets the refresh value.</summary>
    public int Refresh { get; set; }
    /// <summary>Gets or sets the retry value.</summary>
    public int Retry { get; set; }
    /// <summary>Gets or sets the expire value.</summary>
    public int Expire { get; set; }
    /// <summary>Gets or sets the minimum value.</summary>
    public int Minimum { get; set; }
    /// <summary>Gets or sets the negative cache ttl value.</summary>
    public int NegativeCacheTtl { get; set; }
    /// <summary>Gets or sets the record exists value.</summary>
    public bool RecordExists { get; set; }
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Short summary text for executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public SOAAnalysis Raw { get; set; } = new SOAAnalysis();
}
