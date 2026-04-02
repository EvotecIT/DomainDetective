using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
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
    public int ResolvesCount { get; set; }
    public int DoesNotResolveCount { get; set; }
    public int QueryFailedCount { get; set; }
    public int UnknownResolutionCount { get; set; }
    public int SensitiveHighCount { get; set; }
    public int SensitiveModerateCount { get; set; }
    public int AiExposureCount { get; set; }
    public int WeakCertificateCount { get; set; }
    public int SelfSignedCertificateCount { get; set; }
    public IReadOnlyDictionary<string, int> CtSourceCounts { get; set; } = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<SubdomainDiscoveryEntry> Subdomains { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DomainDetective.Narratives.SubdomainsNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SubdomainsNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = Array.Empty<string>();
    public IReadOnlyList<string> Details { get; set; } = Array.Empty<string>();
    [JsonIgnore]
    public SubdomainsAnalysis Raw { get; set; } = null!;
}
