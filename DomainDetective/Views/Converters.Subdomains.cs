using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static SubdomainsInfo Convert(SubdomainsAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var narrative = DomainDetective.Narratives.SubdomainsNarrative.Build(analysis, analysis.Assessments);

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
        var subdomains = analysis.Subdomains ?? Array.Empty<SubdomainDiscoveryEntry>();
        var ctSourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in subdomains)
        {
            foreach (var source in entry.CtSources ?? Array.Empty<string>())
            {
                if (string.IsNullOrWhiteSpace(source))
                {
                    continue;
                }

                ctSourceCounts[source] = ctSourceCounts.TryGetValue(source, out var count) ? count + 1 : 1;
            }
        }

        var resolvesCount = subdomains.Count(static entry => entry.ResolutionStatus == SubdomainResolutionStatus.Resolves);
        var noDnsCount = subdomains.Count(static entry => entry.ResolutionStatus == SubdomainResolutionStatus.DoesNotResolve);
        var failedResolutionCount = subdomains.Count(static entry => entry.ResolutionStatus == SubdomainResolutionStatus.QueryFailed);
        var uncheckedCount = subdomains.Count(static entry => entry.ResolutionStatus == SubdomainResolutionStatus.Unknown);
        var sensitiveHighCount = subdomains.Count(static entry => entry.SensitiveRisk == SensitiveSubdomainRisk.High);
        var sensitiveModerateCount = subdomains.Count(static entry => entry.SensitiveRisk == SensitiveSubdomainRisk.Moderate);
        var aiExposureCount = subdomains.Count(static entry => entry.AiSignals.Count > 0);
        var weakCertificateCount = subdomains.Count(static entry => entry.LatestCertificateWeakKey == true);
        var selfSignedCertificateCount = subdomains.Count(static entry => entry.LatestCertificateIsSelfSigned == true);
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
            ResolvesCount = resolvesCount,
            DoesNotResolveCount = noDnsCount,
            QueryFailedCount = failedResolutionCount,
            UnknownResolutionCount = uncheckedCount,
            SensitiveHighCount = sensitiveHighCount,
            SensitiveModerateCount = sensitiveModerateCount,
            AiExposureCount = aiExposureCount,
            WeakCertificateCount = weakCertificateCount,
            SelfSignedCertificateCount = selfSignedCertificateCount,
            CtSourceCounts = ctSourceCounts,
            Subdomains = subdomains,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(refs, recs)
                .Concat(narrative.References ?? new List<string>())
                .Where(static reference => !string.IsNullOrWhiteSpace(reference))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            Narrative = narrative,
            Highlights = narrative.Highlights?.ToList() ?? new List<string>(),
            Details = narrative.Details?.ToList() ?? new List<string>(),
            Raw = analysis
        };
    }
}

/// <summary>Provides subdomains info functionality.</summary>
public sealed class SubdomainsInfo
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
    /// <summary>Gets or sets the results capped value.</summary>
    public bool ResultsCapped { get; set; }
    /// <summary>Gets or sets the first seen utc value.</summary>
    public DateTimeOffset? FirstSeenUtc { get; set; }
    /// <summary>Gets or sets the last seen utc value.</summary>
    public DateTimeOffset? LastSeenUtc { get; set; }
    /// <summary>Gets or sets the distinct issuer count value.</summary>
    public int DistinctIssuerCount { get; set; }
    /// <summary>Gets or sets the issuer counts value.</summary>
    public IReadOnlyDictionary<string, int> IssuerCounts { get; set; } = null!;
    /// <summary>Gets or sets the subdomain count value.</summary>
    public int SubdomainCount { get; set; }
    /// <summary>Gets or sets the resolution reduced value.</summary>
    public bool ResolutionReduced { get; set; }
    /// <summary>Gets or sets the resolves count value.</summary>
    public int ResolvesCount { get; set; }
    /// <summary>Gets or sets the does not resolve count value.</summary>
    public int DoesNotResolveCount { get; set; }
    /// <summary>Gets or sets the query failed count value.</summary>
    public int QueryFailedCount { get; set; }
    /// <summary>Gets or sets the unknown resolution count value.</summary>
    public int UnknownResolutionCount { get; set; }
    /// <summary>Gets or sets the sensitive high count value.</summary>
    public int SensitiveHighCount { get; set; }
    /// <summary>Gets or sets the sensitive moderate count value.</summary>
    public int SensitiveModerateCount { get; set; }
    /// <summary>Gets or sets the ai exposure count value.</summary>
    public int AiExposureCount { get; set; }
    /// <summary>Gets or sets the weak certificate count value.</summary>
    public int WeakCertificateCount { get; set; }
    /// <summary>Gets or sets the self signed certificate count value.</summary>
    public int SelfSignedCertificateCount { get; set; }
    /// <summary>Gets or sets the ct source counts value.</summary>
    public IReadOnlyDictionary<string, int> CtSourceCounts { get; set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets or sets the subdomains value.</summary>
    public IReadOnlyList<SubdomainDiscoveryEntry> Subdomains { get; set; } = null!;
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
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.SubdomainsNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SubdomainsNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public SubdomainsAnalysis Raw { get; set; } = null!;
}
