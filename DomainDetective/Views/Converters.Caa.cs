using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static CaaInfo Convert(CAAAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new CaaInfo
        {
            Check = HealthCheckType.CAA,
            Area = AreaForKind(HealthCheckType.CAA),
            Subject = analysis.Subject ?? analysis.DomainName,
            ValidRecords = analysis.ValidRecords,
            InvalidRecords = analysis.InvalidRecords,
            Conflicting = analysis.Conflicting,
            HasDuplicateIssuers = analysis.HasDuplicateIssuers,
            CanIssueCertificatesForDomain = analysis.CanIssueCertificatesForDomain,
            CanIssueWildcardCertificatesForDomain = analysis.CanIssueWildcardCertificatesForDomain,
            CanIssueMail = analysis.CanIssueMail,
            ReportViolationEmail = analysis.ReportViolationEmail,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"valid {analysis.ValidRecords}, invalid {analysis.InvalidRecords}; wildcard {(analysis.CanIssueWildcardCertificatesForDomain?.Count>0?"yes":"no")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing CAA (Certificate Authority Authorization) analysis.
/// </summary>
public class CaaInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    public int ValidRecords { get; set; }
    public int InvalidRecords { get; set; }
    public bool Conflicting { get; set; }
    public bool HasDuplicateIssuers { get; set; }
    /// <summary>Issuers authorized to issue domain certificates.</summary>
    public IReadOnlyList<string> CanIssueCertificatesForDomain { get; set; } = System.Array.Empty<string>();
    /// <summary>Issuers authorized to issue wildcard certificates.</summary>
    public IReadOnlyList<string> CanIssueWildcardCertificatesForDomain { get; set; } = System.Array.Empty<string>();
    /// <summary>Issuers authorized for S/MIME.</summary>
    public IReadOnlyList<string> CanIssueMail { get; set; } = System.Array.Empty<string>();
    /// <summary>Email addresses for iodef report notifications.</summary>
    public IReadOnlyList<string> ReportViolationEmail { get; set; } = System.Array.Empty<string>();
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    /// <summary>Short summary text used in executive summaries.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public CAAAnalysis Raw { get; set; } = new CAAAnalysis();
}
