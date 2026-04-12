using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
            Subject = analysis.Subject ?? string.Empty,
            SrvRecordExists = analysis.SrvRecordExists,
            SrvTarget = analysis.SrvTarget ?? string.Empty,
            SrvPort = analysis.SrvPort,
            AutoconfigCnameExists = analysis.AutoconfigCnameExists,
            AutoconfigTarget = analysis.AutoconfigTarget ?? string.Empty,
            AutodiscoverCnameExists = analysis.AutodiscoverCnameExists,
            AutodiscoverTarget = analysis.AutodiscoverTarget ?? string.Empty,
            Endpoints = endpoints,
            AttemptedEndpoints = attempts,
            XmlValidFound = valid != null,
            BestEndpointUrl = bestUrl ?? string.Empty,
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

/// <summary>
/// View model summarizing Autodiscover DNS/HTTP results for reporting.
/// </summary>
public class AutodiscoverInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area this result belongs to.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Domain the analysis applies to.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>True when an _autodiscover._tcp SRV record is present.</summary>
    public bool SrvRecordExists { get; set; }
    /// <summary>Target host from SRV record.</summary>
    public string SrvTarget { get; set; } = string.Empty;
    /// <summary>Port from SRV record.</summary>
    public int SrvPort { get; set; }
    /// <summary>True when autoconfig CNAME exists.</summary>
    public bool AutoconfigCnameExists { get; set; }
    /// <summary>Target of autoconfig CNAME.</summary>
    public string AutoconfigTarget { get; set; } = string.Empty;
    /// <summary>True when autodiscover CNAME exists.</summary>
    public bool AutodiscoverCnameExists { get; set; }
    /// <summary>Target of autodiscover CNAME.</summary>
    public string AutodiscoverTarget { get; set; } = string.Empty;
    /// <summary>HTTP probe results in discovery order.</summary>
    public IReadOnlyList<AutodiscoverEndpointResult> Endpoints { get; set; } = System.Array.Empty<AutodiscoverEndpointResult>();
    /// <summary>Total HTTP endpoints attempted.</summary>
    public int AttemptedEndpoints { get; set; }
    /// <summary>True if any endpoint produced valid XML.</summary>
    public bool XmlValidFound { get; set; }
    /// <summary>URL considered most promising (valid XML/JSON or first attempt).</summary>
    public string BestEndpointUrl { get; set; } = string.Empty;
    /// <summary>Status code for the best endpoint (if any).</summary>
    public int? BestEndpointStatus { get; set; }
    /// <summary>Number of HTTPS attempts.</summary>
    public int HttpsAttempts { get; set; }
    /// <summary>Number of HTTP attempts.</summary>
    public int HttpAttempts { get; set; }
    /// <summary>Number of successful responses (2xx).</summary>
    public int SuccessfulResponses { get; set; }
    /// <summary>Redirect hop count for the best endpoint.</summary>
    public int RedirectsForBest { get; set; }
    /// <summary>Structured assessment list underpinning the status.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Short summary string for executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable guidance derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture findings.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links relevant to this check.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis object.</summary>
    public AutodiscoverAnalysis Raw { get; set; } = new AutodiscoverAnalysis();
}
