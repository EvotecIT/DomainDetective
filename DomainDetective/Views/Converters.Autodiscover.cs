using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static AutodiscoverInfo Convert(AutodiscoverAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var endpoints = analysis.Endpoints ?? new List<AutodiscoverEndpointResult>();
        var attempts = endpoints.Count;
        var valid = System.Linq.Enumerable.FirstOrDefault(endpoints, e => e.XmlValid || e.JsonValid);
        var first = System.Linq.Enumerable.FirstOrDefault(endpoints);
        var bestUrl = valid?.FinalUrl ?? valid?.Url ?? first?.FinalUrl ?? first?.Url;
        var bestStatus = valid?.StatusCode ?? first?.StatusCode;
        var httpsAttempts = System.Linq.Enumerable.Count(endpoints, e => (e.Url ?? string.Empty).StartsWith("https://", System.StringComparison.OrdinalIgnoreCase));
        var httpAttempts = attempts - httpsAttempts;
        var successCount = System.Linq.Enumerable.Count(endpoints, e => e.StatusCode >= 200 && e.StatusCode < 300);
        var redirectsForBest = valid?.RedirectChain?.Count ?? first?.RedirectChain?.Count ?? 0;

        return new AutodiscoverInfo
        {
            Check = HealthCheckType.AUTODISCOVER,
            Area = AreaForKind(HealthCheckType.AUTODISCOVER),
            Subject = analysis.Subject,
            SrvRecordExists = analysis.SrvRecordExists,
            SrvTarget = analysis.SrvTarget,
            SrvPort = analysis.SrvPort,
            AutoconfigCnameExists = analysis.AutoconfigCnameExists,
            AutoconfigTarget = analysis.AutoconfigTarget,
            AutodiscoverCnameExists = analysis.AutodiscoverCnameExists,
            AutodiscoverTarget = analysis.AutodiscoverTarget,
            Endpoints = endpoints,
            AttemptedEndpoints = attempts,
            XmlValidFound = valid != null,
            BestEndpointUrl = bestUrl,
            BestEndpointStatus = bestStatus,
            HttpsAttempts = httpsAttempts,
            HttpAttempts = httpAttempts,
            SuccessfulResponses = successCount,
            RedirectsForBest = redirectsForBest,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"SRV {(analysis.SrvRecordExists?"yes":"no")}; CNAME {(analysis.AutodiscoverCnameExists?"yes":"no")}; HTTP {(successCount>0?"ok":"fail")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class AutodiscoverInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public bool SrvRecordExists { get; set; }
    public string SrvTarget { get; set; } = string.Empty;
    public int SrvPort { get; set; }
    public bool AutoconfigCnameExists { get; set; }
    public string AutoconfigTarget { get; set; } = string.Empty;
    public bool AutodiscoverCnameExists { get; set; }
    public string AutodiscoverTarget { get; set; } = string.Empty;
    public IReadOnlyList<AutodiscoverEndpointResult> Endpoints { get; set; } = System.Array.Empty<AutodiscoverEndpointResult>();
    public int AttemptedEndpoints { get; set; }
    public bool XmlValidFound { get; set; }
    public string BestEndpointUrl { get; set; } = string.Empty;
    public int? BestEndpointStatus { get; set; }
    public int HttpsAttempts { get; set; }
    public int HttpAttempts { get; set; }
    public int SuccessfulResponses { get; set; }
    public int RedirectsForBest { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public AutodiscoverAnalysis Raw { get; set; } = new AutodiscoverAnalysis();
}
