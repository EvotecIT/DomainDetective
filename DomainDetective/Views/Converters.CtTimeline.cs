using System;
using System.Collections.Generic;
using System.Globalization;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public sealed class CtTimelineInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool QuerySucceeded { get; set; }
    public string? FailureReason { get; set; }
    public int CertificateObservationCount { get; set; }
    public int UniqueCertificateCount { get; set; }
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public IReadOnlyDictionary<string, int> IssuerCounts { get; set; } = null!;
    public int ActiveCertificateCount { get; set; }
    public int ExpiredCertificateCount { get; set; }
    public int NotYetValidCertificateCount { get; set; }
    public int WildcardCertificateCount { get; set; }
    public int IssuedLast7Days { get; set; }
    public int IssuedLast30Days { get; set; }
    public bool ResultsCapped { get; set; }
    public IReadOnlyList<CtTimelineBucket> Timeline { get; set; } = null!;
    public IReadOnlyList<CtCertificateSample> RecentCertificates { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public CertificateTransparencyTimelineAnalysis Raw { get; set; } = null!;
}

