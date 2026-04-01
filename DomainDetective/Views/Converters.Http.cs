using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static HttpInfo Convert(HttpAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var grade = ComputeHttpGrade(analysis);
        var narrative = DomainDetective.Narratives.HttpNarrative.Build(analysis);
	        return new HttpInfo
	        {
	            Check = HealthCheckType.HTTP,
	            Area = AreaForKind(HealthCheckType.HTTP),
	            Subject = analysis.Subject,
	            Url = analysis.Subject,
	            RequestMethodUsed = analysis.RequestMethodUsed,
	            ProxyUsed = analysis.ProxyUsed,
	            TlsValidationDisabled = analysis.TlsValidationDisabled,
	            RequestHeaderNames = analysis.RequestHeaderNames,
	            IsReachable = analysis.IsReachable,
                FailureReason = analysis.FailureReason,
	            StatusCode = analysis.StatusCode,
	            BodyLength = analysis.BodyLength,
	            BodySha256 = analysis.BodySha256,
	            ResponseTime = analysis.ResponseTime,
                ProtocolVersion = analysis.ProtocolVersion?.ToString(),
            Nel = analysis.NelRaw,
            ReportTo = analysis.ReportToRaw,
            SpeculationRules = analysis.SpeculationRulesRaw,
                ServerHeader = analysis.ServerHeader,
            HstsPresent = analysis.HstsPresent,
                HstsMaxAge = analysis.HstsMaxAge,
                HstsIncludesSubDomains = analysis.HstsIncludesSubDomains,
                HstsTooShort = analysis.HstsTooShort,
            HstsPreloaded = analysis.HstsPreloaded,
                HstsPreloadDirectivePresent = analysis.HstsPreloadDirectivePresent,
            HstsPreloadEligible = analysis.HstsPreloadEligible,
                XssProtectionPresent = analysis.XssProtectionPresent,
                ExpectCtPresent = analysis.ExpectCtPresent,
                ExpectCtMaxAge = analysis.ExpectCtMaxAge,
                ExpectCtReportUri = analysis.ExpectCtReportUri,
                CspUnsafeDirectives = analysis.CspUnsafeDirectives,
	            Http2Supported = analysis.Http2Supported,
	            Http3Supported = analysis.Http3Supported,
	            MixedContentDetected = analysis.MixedContentDetected,
                InsecureFormsCount = analysis.InsecureFormsCount,
                InsecureFormActions = analysis.InsecureFormActions,
                PermissionsPolicyPresent = analysis.PermissionsPolicyPresent,
                PermissionsPolicy = analysis.PermissionsPolicy,
                ReferrerPolicy = analysis.ReferrerPolicy,
                XFrameOptions = analysis.XFrameOptions,
                CrossOriginOpenerPolicy = analysis.CrossOriginOpenerPolicy,
                CrossOriginEmbedderPolicy = analysis.CrossOriginEmbedderPolicy,
                CrossOriginResourcePolicy = analysis.CrossOriginResourcePolicy,
                XPermittedCrossDomainPolicies = analysis.XPermittedCrossDomainPolicies,
                OriginAgentClusterPresent = analysis.OriginAgentClusterPresent,
                OriginAgentClusterEnabled = analysis.OriginAgentClusterEnabled,
	            CspFrameAncestorsPresent = analysis.CspFrameAncestorsPresent,
                SecurityHeaders = analysis.SecurityHeaders.ToDictionary(static entry => entry.Key, static entry => entry.Value.Value),
                VisitedUrls = analysis.VisitedUrls,
	            InformationDisclosureHeaders = analysis.InformationDisclosureHeaders,
	            CachingHeaders = analysis.CachingHeaders,
	            DeprecatedHeadersPresent = analysis.DeprecatedHeadersPresent,
	            MissingDeprecatedHeaders = analysis.MissingDeprecatedHeaders,
	            MissingSecurityHeaders = analysis.MissingSecurityHeaders,
	            Grade = grade,
	            Assessments = analysis.Assessments,
	            Status = status,
	            WarningCount = warnCount,
	            ErrorCount = errCount,
	            Summary = $"{analysis.RequestMethodUsed}; {(analysis.Http2Supported ? "H2" : "no H2")}/{(analysis.Http3Supported ? "H3" : "no H3")}; HSTS {(analysis.HstsPresent ? "yes" : "no")}; forms {(analysis.InsecureFormsCount > 0 ? $"insecure {analysis.InsecureFormsCount}" : "ok")}; missing {analysis.MissingSecurityHeaders?.Count ?? 0}; grade {grade.ToLetter()}; {(analysis.StatusCode?.ToString() ?? "")}",
                Narrative = narrative,
                Highlights = narrative.Highlights,
                Details = narrative.Details,
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
    public string? Subject { get; set; }
    public string? Url { get; set; }
    public HttpRequestMethod RequestMethodUsed { get; set; }
    public string? ProxyUsed { get; set; }
    public bool TlsValidationDisabled { get; set; }
    public IReadOnlyList<string> RequestHeaderNames { get; set; } = null!;
    public bool IsReachable { get; set; }
    public string? FailureReason { get; set; }
    public int? StatusCode { get; set; }
    public int? BodyLength { get; set; }
    public string? BodySha256 { get; set; }
    public System.TimeSpan ResponseTime { get; set; }
    public string? ProtocolVersion { get; set; }
    public string? Nel { get; set; }
    public string? ReportTo { get; set; }
    public string? SpeculationRules { get; set; }
    public string? ServerHeader { get; set; }
    public bool HstsPresent { get; set; }
    public int? HstsMaxAge { get; set; }
    public bool HstsIncludesSubDomains { get; set; }
    public bool HstsTooShort { get; set; }
    public bool HstsPreloaded { get; set; }
    public bool HstsPreloadDirectivePresent { get; set; }
    public bool HstsPreloadEligible { get; set; }
    public bool XssProtectionPresent { get; set; }
    public bool ExpectCtPresent { get; set; }
    public int? ExpectCtMaxAge { get; set; }
    public string? ExpectCtReportUri { get; set; }
    public bool CspUnsafeDirectives { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public bool MixedContentDetected { get; set; }
    public int InsecureFormsCount { get; set; }
    public IReadOnlyList<string> InsecureFormActions { get; set; } = System.Array.Empty<string>();
    public bool PermissionsPolicyPresent { get; set; }
    public IReadOnlyDictionary<string, string> PermissionsPolicy { get; set; } = null!;
    public string? ReferrerPolicy { get; set; }
    public string? XFrameOptions { get; set; }
    public string? CrossOriginOpenerPolicy { get; set; }
    public string? CrossOriginEmbedderPolicy { get; set; }
    public string? CrossOriginResourcePolicy { get; set; }
    public string? XPermittedCrossDomainPolicies { get; set; }
    public bool OriginAgentClusterPresent { get; set; }
    public bool OriginAgentClusterEnabled { get; set; }
    public bool CspFrameAncestorsPresent { get; set; }
    public IReadOnlyDictionary<string, string> SecurityHeaders { get; set; } = null!;
    public IReadOnlyList<string> VisitedUrls { get; set; } = null!;
    public IReadOnlyDictionary<string, string> InformationDisclosureHeaders { get; set; } = null!;
    public IReadOnlyDictionary<string, string> CachingHeaders { get; set; } = null!;
    public IReadOnlyCollection<string> DeprecatedHeadersPresent { get; set; } = null!;
    public IReadOnlyCollection<string> MissingDeprecatedHeaders { get; set; } = null!;
    public IReadOnlyCollection<string> MissingSecurityHeaders { get; set; } = null!;
    public GradeLevel Grade { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public DomainDetective.Narratives.HttpNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.HttpNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    [JsonIgnore]
    public HttpAnalysis Raw { get; set; } = null!;
}
