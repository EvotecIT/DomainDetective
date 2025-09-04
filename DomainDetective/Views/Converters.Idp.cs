using System.Collections.Generic;
namespace DomainDetective.Views;

public static partial class Converters
{
    public static IdpInfoView Convert(IdpInfoAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        return new IdpInfoView
        {
            Check = HealthCheckType.MESSAGEHEADER, // closest area; no dedicated HC yet
            Area = AnalysisArea.Mail,
            Subject = analysis.Domain,
            DiscoveryUrl = analysis.DiscoveryUrl,
            TenantId = analysis.TenantId,
            NameSpaceType = analysis.NameSpaceType,
            FederatedAuthUrl = analysis.FederatedAuthUrl,
            DiscoverySucceeded = analysis.DiscoverySucceeded,
            GetUserRealmSucceeded = analysis.GetUserRealmSucceeded,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"Tenant {(string.IsNullOrWhiteSpace(analysis.TenantId) ? "?" : analysis.TenantId)}; Namespace {analysis.NameSpaceType ?? "?"}",
            Raw = analysis
        };
    }
}

public sealed class IdpInfoView
{
    /// <summary>Logical check identifier (closest area; reused).</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>High-level analysis area (Mail).</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Domain used for probing identity endpoints.</summary>
    public string? Subject { get; set; }
    /// <summary>OIDC discovery URL that succeeded, when any.</summary>
    public string? DiscoveryUrl { get; set; }
    /// <summary>Tenant identifier parsed from token endpoint path (if present).</summary>
    public string? TenantId { get; set; }
    /// <summary>Tenant namespace type returned by GetUserRealm (e.g., Managed/Federated).</summary>
    public string? NameSpaceType { get; set; }
    /// <summary>Federated authentication URL returned by GetUserRealm.</summary>
    public string? FederatedAuthUrl { get; set; }
    /// <summary>True when OIDC discovery completed successfully.</summary>
    public bool DiscoverySucceeded { get; set; }
    /// <summary>True when GetUserRealm returned a 200 response and was parsed.</summary>
    public bool GetUserRealmSucceeded { get; set; }
    /// <summary>Structured assessments captured during analysis.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; }
    /// <summary>Computed status string (OK/Warning/Error) from assessments.</summary>
    public string Status { get; set; }
    /// <summary>Total number of warnings encountered.</summary>
    public int WarningCount { get; set; }
    /// <summary>Total number of errors encountered.</summary>
    public int ErrorCount { get; set; }
    /// <summary>One-line summary containing key IdP hints.</summary>
    public string Summary { get; set; }
    /// <summary>Raw analysis object.</summary>
    public IdpInfoAnalysis Raw { get; set; }
}
