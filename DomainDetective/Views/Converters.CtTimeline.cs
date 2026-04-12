using System;
using System.Collections.Generic;
using System.Globalization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static CtTimelineInfo Convert(CertificateTransparencyTimelineAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        var refs = new[]
        {
            new StandardReference { Title = "Certificate Transparency", Reference = "RFC 6962", Url = "https://datatracker.ietf.org/doc/html/rfc6962" }
        };

        string FormatDate(DateTimeOffset? dt) => dt.HasValue ? dt.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "-";

        var summary = $"{analysis.UniqueCertificateCount} cert(s) (active {analysis.ActiveCertificateCount}, expired {analysis.ExpiredCertificateCount}); issuers {analysis.DistinctIssuerCount}; first {FormatDate(analysis.FirstSeenUtc)}; last {FormatDate(analysis.LastSeenUtc)}; 7d {analysis.IssuedLast7Days}; 30d {analysis.IssuedLast30Days}{(analysis.ResultsCapped ? "; capped" : string.Empty)}";

        return new CtTimelineInfo
        {
            Check = HealthCheckType.CTTIMELINE,
            Area = AreaForKind(HealthCheckType.CTTIMELINE),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            FailureReason = analysis.FailureReason,
            CertificateObservationCount = analysis.CertificateObservationCount,
            UniqueCertificateCount = analysis.UniqueCertificateCount,
            FirstSeenUtc = analysis.FirstSeenUtc,
            LastSeenUtc = analysis.LastSeenUtc,
            IssuerCounts = analysis.IssuerCounts,
            ActiveCertificateCount = analysis.ActiveCertificateCount,
            ExpiredCertificateCount = analysis.ExpiredCertificateCount,
            NotYetValidCertificateCount = analysis.NotYetValidCertificateCount,
            WildcardCertificateCount = analysis.WildcardCertificateCount,
            IssuedLast7Days = analysis.IssuedLast7Days,
            IssuedLast30Days = analysis.IssuedLast30Days,
            ResultsCapped = analysis.ResultsCapped,
            Timeline = analysis.Timeline,
            RecentCertificates = analysis.RecentCertificates,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(refs, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides ct timeline info functionality.</summary>
public sealed class CtTimelineInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the certificate observation count value.</summary>
    public int CertificateObservationCount { get; set; }
    /// <summary>Gets or sets the unique certificate count value.</summary>
    public int UniqueCertificateCount { get; set; }
    /// <summary>Gets or sets the first seen utc value.</summary>
    public DateTimeOffset? FirstSeenUtc { get; set; }
    /// <summary>Gets or sets the last seen utc value.</summary>
    public DateTimeOffset? LastSeenUtc { get; set; }
    /// <summary>Gets or sets the issuer counts value.</summary>
    public IReadOnlyDictionary<string, int> IssuerCounts { get; set; } = null!;
    /// <summary>Gets or sets the active certificate count value.</summary>
    public int ActiveCertificateCount { get; set; }
    /// <summary>Gets or sets the expired certificate count value.</summary>
    public int ExpiredCertificateCount { get; set; }
    /// <summary>Gets or sets the not yet valid certificate count value.</summary>
    public int NotYetValidCertificateCount { get; set; }
    /// <summary>Gets or sets the wildcard certificate count value.</summary>
    public int WildcardCertificateCount { get; set; }
    /// <summary>Gets or sets the issued last7 days value.</summary>
    public int IssuedLast7Days { get; set; }
    /// <summary>Gets or sets the issued last30 days value.</summary>
    public int IssuedLast30Days { get; set; }
    /// <summary>Gets or sets the results capped value.</summary>
    public bool ResultsCapped { get; set; }
    /// <summary>Gets or sets the timeline value.</summary>
    public IReadOnlyList<CtTimelineBucket> Timeline { get; set; } = null!;
    /// <summary>Gets or sets the recent certificates value.</summary>
    public IReadOnlyList<CtCertificateSample> RecentCertificates { get; set; } = null!;
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
    public CertificateTransparencyTimelineAnalysis Raw { get; set; } = null!;
}

