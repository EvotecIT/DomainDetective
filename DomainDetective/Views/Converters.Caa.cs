using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static CaaInfo Convert(CAAAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
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
            References = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Raw = analysis
        };
    }
}

public class CaaInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int ValidRecords { get; set; }
    public int InvalidRecords { get; set; }
    public bool Conflicting { get; set; }
    public bool HasDuplicateIssuers { get; set; }
    public IReadOnlyList<string> CanIssueCertificatesForDomain { get; set; }
    public IReadOnlyList<string> CanIssueWildcardCertificatesForDomain { get; set; }
    public IReadOnlyList<string> CanIssueMail { get; set; }
    public IReadOnlyList<string> ReportViolationEmail { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public CAAAnalysis Raw { get; set; }
}
