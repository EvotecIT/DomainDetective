using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SubdomainsInfo Convert(SubdomainsAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        var refs = new[]
        {
            new StandardReference { Title = "Certificate Transparency", Reference = "RFC 6962", Url = "https://datatracker.ietf.org/doc/html/rfc6962" }
        };

        string range = "-";
        if (analysis.FirstSeenUtc.HasValue || analysis.LastSeenUtc.HasValue)
        {
            var a = analysis.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
            var b = analysis.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
            range = a + " .. " + b;
        }

        var subCount = analysis.Subdomains?.Count ?? 0;
        var summary = $"{subCount} subdomain(s); issuers {analysis.DistinctIssuerCount}; CT rows {analysis.CertificateObservationCount}; CT {(analysis.ResultsCapped ? "capped" : "ok")}; seen {range}; dns-checks {(analysis.VerifyStillResolves ? (analysis.ResolutionReduced ? "capped" : "ok") : "off")}";

        return new SubdomainsInfo
        {
            Check = HealthCheckType.SUBDOMAINS,
            Area = AreaForKind(HealthCheckType.SUBDOMAINS),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            FailureReason = analysis.FailureReason,
            CertificateObservationCount = analysis.CertificateObservationCount,
            FirstSeenUtc = analysis.FirstSeenUtc,
            LastSeenUtc = analysis.LastSeenUtc,
            DistinctIssuerCount = analysis.DistinctIssuerCount,
            IssuerCounts = analysis.IssuerCounts,
            SubdomainCount = subCount,
            ResolutionReduced = analysis.ResolutionReduced,
            ResultsCapped = analysis.ResultsCapped,
            Subdomains = analysis.Subdomains ?? Array.Empty<SubdomainDiscoveryEntry>(),
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

public sealed class SubdomainsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool QuerySucceeded { get; set; }
    public string? FailureReason { get; set; }
    public int CertificateObservationCount { get; set; }
    public bool ResultsCapped { get; set; }
    public DateTimeOffset? FirstSeenUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
    public int DistinctIssuerCount { get; set; }
    public IReadOnlyDictionary<string, int> IssuerCounts { get; set; } = null!;
    public int SubdomainCount { get; set; }
    public bool ResolutionReduced { get; set; }
    public IReadOnlyList<SubdomainDiscoveryEntry> Subdomains { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public SubdomainsAnalysis Raw { get; set; } = null!;
}
