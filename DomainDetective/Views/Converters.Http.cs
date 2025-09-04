using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static HttpInfo Convert(HttpAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var grade = ComputeHttpGrade(analysis);
        return new HttpInfo
        {
            Check = HealthCheckType.HTTP,
            Area = AreaForKind(HealthCheckType.HTTP),
            Subject = analysis.Subject,
            Url = analysis.Subject,
            IsReachable = analysis.IsReachable,
            StatusCode = analysis.StatusCode,
            BodyLength = analysis.BodyLength,
            BodySha256 = analysis.BodySha256,
            ResponseTime = analysis.ResponseTime,
            Nel = analysis.NelRaw,
            ReportTo = analysis.ReportToRaw,
            SpeculationRules = analysis.SpeculationRulesRaw,
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
            Summary = $"{(analysis.Http2Supported ? "H2" : "no H2")}/{(analysis.Http3Supported ? "H3" : "no H3")}; HSTS {(analysis.HstsPresent ? "yes" : "no")}; forms {(analysis.InsecureFormsCount > 0 ? $"insecure {analysis.InsecureFormsCount}" : "ok")}; missing {analysis.MissingSecurityHeaders?.Count ?? 0}; grade {grade.ToLetter()}; {(analysis.StatusCode?.ToString() ?? "")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

    private static GradeLevel ComputeHttpGrade(HttpAnalysis analysis)
    {
        if (analysis == null) return GradeLevel.Unknown;
        if (!analysis.IsReachable) return GradeLevel.F;
        if (analysis.MixedContentDetected) return GradeLevel.F;

        // Score based on presence of core headers
        var present = 0;
        bool Has(string name) => analysis.SecurityHeaders?.ContainsKey(name) == true;
        if (Has("Strict-Transport-Security")) present++;
        if (Has("Content-Security-Policy")) present++;
        if (Has("Referrer-Policy")) present++;
        if (Has("X-Content-Type-Options")) present++;
        if (Has("X-Frame-Options")) present++;
        if (Has("Permissions-Policy")) present++;

        return present switch {
            >= 6 => GradeLevel.A,
            5 => GradeLevel.B,
            4 => GradeLevel.C,
            2 or 3 => GradeLevel.D,
            _ => GradeLevel.F
        };
    }
}

public class HttpInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string Url { get; set; }
    public bool IsReachable { get; set; }
    public int? StatusCode { get; set; }
    public int? BodyLength { get; set; }
    public string? BodySha256 { get; set; }
    public System.TimeSpan ResponseTime { get; set; }
    public string? Nel { get; set; }
    public string? ReportTo { get; set; }
    public string? SpeculationRules { get; set; }
    public bool HstsPresent { get; set; }
    public bool HstsPreloaded { get; set; }
    public bool HstsPreloadEligible { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public bool MixedContentDetected { get; set; }
    public IReadOnlyCollection<string> MissingSecurityHeaders { get; set; }
    public GradeLevel Grade { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public HttpAnalysis Raw { get; set; }
}
