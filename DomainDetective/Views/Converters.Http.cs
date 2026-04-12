using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides http info functionality.</summary>
public class HttpInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the url value.</summary>
    public string? Url { get; set; }
    /// <summary>Gets or sets the request method used value.</summary>
    public HttpRequestMethod RequestMethodUsed { get; set; }
    /// <summary>Gets or sets the proxy used value.</summary>
    public string? ProxyUsed { get; set; }
    /// <summary>Gets or sets the tls validation disabled value.</summary>
    public bool TlsValidationDisabled { get; set; }
    /// <summary>Gets or sets the request header names value.</summary>
    public IReadOnlyList<string> RequestHeaderNames { get; set; } = null!;
    /// <summary>Gets or sets the is reachable value.</summary>
    public bool IsReachable { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the status code value.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Gets or sets the body length value.</summary>
    public int? BodyLength { get; set; }
    /// <summary>Gets or sets the body sha256 value.</summary>
    public string? BodySha256 { get; set; }
    /// <summary>Gets or sets the response time value.</summary>
    public System.TimeSpan ResponseTime { get; set; }
    /// <summary>Gets or sets the protocol version value.</summary>
    public string? ProtocolVersion { get; set; }
    /// <summary>Gets or sets the nel value.</summary>
    public string? Nel { get; set; }
    /// <summary>Gets or sets the report to value.</summary>
    public string? ReportTo { get; set; }
    /// <summary>Gets or sets the speculation rules value.</summary>
    public string? SpeculationRules { get; set; }
    /// <summary>Gets or sets the server header value.</summary>
    public string? ServerHeader { get; set; }
    /// <summary>Gets or sets the hsts present value.</summary>
    public bool HstsPresent { get; set; }
    /// <summary>Gets or sets the hsts max age value.</summary>
    public int? HstsMaxAge { get; set; }
    /// <summary>Gets or sets the hsts includes sub domains value.</summary>
    public bool HstsIncludesSubDomains { get; set; }
    /// <summary>Gets or sets the hsts too short value.</summary>
    public bool HstsTooShort { get; set; }
    /// <summary>Gets or sets the hsts preloaded value.</summary>
    public bool HstsPreloaded { get; set; }
    /// <summary>Gets or sets the hsts preload directive present value.</summary>
    public bool HstsPreloadDirectivePresent { get; set; }
    /// <summary>Gets or sets the hsts preload eligible value.</summary>
    public bool HstsPreloadEligible { get; set; }
    /// <summary>Gets or sets the xss protection present value.</summary>
    public bool XssProtectionPresent { get; set; }
    /// <summary>Gets or sets the expect ct present value.</summary>
    public bool ExpectCtPresent { get; set; }
    /// <summary>Gets or sets the expect ct max age value.</summary>
    public int? ExpectCtMaxAge { get; set; }
    /// <summary>Gets or sets the expect ct report uri value.</summary>
    public string? ExpectCtReportUri { get; set; }
    /// <summary>Gets or sets the csp unsafe directives value.</summary>
    public bool CspUnsafeDirectives { get; set; }
    /// <summary>Gets or sets the http2 supported value.</summary>
    public bool Http2Supported { get; set; }
    /// <summary>Gets or sets the http3 supported value.</summary>
    public bool Http3Supported { get; set; }
    /// <summary>Gets or sets the mixed content detected value.</summary>
    public bool MixedContentDetected { get; set; }
    /// <summary>Gets or sets the insecure forms count value.</summary>
    public int InsecureFormsCount { get; set; }
    /// <summary>Gets or sets the insecure form actions value.</summary>
    public IReadOnlyList<string> InsecureFormActions { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the permissions policy present value.</summary>
    public bool PermissionsPolicyPresent { get; set; }
    /// <summary>Gets or sets the permissions policy value.</summary>
    public IReadOnlyDictionary<string, string> PermissionsPolicy { get; set; } = null!;
    /// <summary>Gets or sets the referrer policy value.</summary>
    public string? ReferrerPolicy { get; set; }
    /// <summary>Gets or sets the x frame options value.</summary>
    public string? XFrameOptions { get; set; }
    /// <summary>Gets or sets the cross origin opener policy value.</summary>
    public string? CrossOriginOpenerPolicy { get; set; }
    /// <summary>Gets or sets the cross origin embedder policy value.</summary>
    public string? CrossOriginEmbedderPolicy { get; set; }
    /// <summary>Gets or sets the cross origin resource policy value.</summary>
    public string? CrossOriginResourcePolicy { get; set; }
    /// <summary>Gets or sets the x permitted cross domain policies value.</summary>
    public string? XPermittedCrossDomainPolicies { get; set; }
    /// <summary>Gets or sets the origin agent cluster present value.</summary>
    public bool OriginAgentClusterPresent { get; set; }
    /// <summary>Gets or sets the origin agent cluster enabled value.</summary>
    public bool OriginAgentClusterEnabled { get; set; }
    /// <summary>Gets or sets the csp frame ancestors present value.</summary>
    public bool CspFrameAncestorsPresent { get; set; }
    /// <summary>Gets or sets the security headers value.</summary>
    public IReadOnlyDictionary<string, string> SecurityHeaders { get; set; } = null!;
    /// <summary>Gets or sets the visited urls value.</summary>
    public IReadOnlyList<string> VisitedUrls { get; set; } = null!;
    /// <summary>Gets or sets the information disclosure headers value.</summary>
    public IReadOnlyDictionary<string, string> InformationDisclosureHeaders { get; set; } = null!;
    /// <summary>Gets or sets the caching headers value.</summary>
    public IReadOnlyDictionary<string, string> CachingHeaders { get; set; } = null!;
    /// <summary>Gets or sets the deprecated headers present value.</summary>
    public IReadOnlyCollection<string> DeprecatedHeadersPresent { get; set; } = null!;
    /// <summary>Gets or sets the missing deprecated headers value.</summary>
    public IReadOnlyCollection<string> MissingDeprecatedHeaders { get; set; } = null!;
    /// <summary>Gets or sets the missing security headers value.</summary>
    public IReadOnlyCollection<string> MissingSecurityHeaders { get; set; } = null!;
    /// <summary>Gets or sets the grade value.</summary>
    public GradeLevel Grade { get; set; }
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
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.HttpNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.HttpNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public HttpAnalysis Raw { get; set; } = null!;
}
