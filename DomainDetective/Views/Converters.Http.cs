using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static HttpInfo Convert(HttpAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var grade = ComputeHttpGrade(analysis);
        return new HttpInfo
        {
            Check = "HTTP",
            Area = AreaFor("HTTP"),
            Subject = analysis.Subject,
            Url = analysis.Subject,
            IsReachable = analysis.IsReachable,
            StatusCode = analysis.StatusCode,
            ResponseTime = analysis.ResponseTime,
            HstsPresent = analysis.HstsPresent,
            HstsPreloaded = analysis.HstsPreloaded,
            HstsPreloadEligible = analysis.HstsPreloadEligible,
            Http2Supported = analysis.Http2Supported,
            Http3Supported = analysis.Http3Supported,
            MixedContentDetected = analysis.MixedContentDetected,
            MissingSecurityHeaders = analysis.MissingSecurityHeaders,
            Grade = grade,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{(analysis.Http2Supported ? "H2" : "no H2")}/{(analysis.Http3Supported ? "H3" : "no H3")}; HSTS {(analysis.HstsPresent ? "yes" : "no")}; missing {analysis.MissingSecurityHeaders?.Count ?? 0}; grade {grade}; {(analysis.StatusCode?.ToString() ?? "")}",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    private static string ComputeHttpGrade(HttpAnalysis analysis)
    {
        if (analysis == null) return string.Empty;
        if (!analysis.IsReachable) return "F";
        if (analysis.MixedContentDetected) return "F";

        // Score based on presence of core headers
        var present = 0;
        bool Has(string name) => analysis.SecurityHeaders?.ContainsKey(name) == true;
        if (Has("Strict-Transport-Security")) present++;
        if (Has("Content-Security-Policy")) present++;
        if (Has("Referrer-Policy")) present++;
        if (Has("X-Content-Type-Options")) present++;
        if (Has("X-Frame-Options")) present++;
        if (Has("Permissions-Policy")) present++;

        // Simple letter mapping
        return present switch {
            >= 6 => "A",
            5 => "B",
            4 => "C",
            2 or 3 => "D",
            _ => "F"
        };
    }
}

public class HttpInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public string Url { get; set; }
    public bool IsReachable { get; set; }
    public int? StatusCode { get; set; }
    public System.TimeSpan ResponseTime { get; set; }
    public bool HstsPresent { get; set; }
    public bool HstsPreloaded { get; set; }
    public bool HstsPreloadEligible { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public bool MixedContentDetected { get; set; }
    public IReadOnlyCollection<string> MissingSecurityHeaders { get; set; }
    public string Grade { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public HttpAnalysis Raw { get; set; }
}
