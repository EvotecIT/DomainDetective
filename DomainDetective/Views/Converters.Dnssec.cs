using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static DnssecStatusInfo Convert(DnsSecAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new DnssecStatusInfo
        {
            Check = HealthCheckType.DNSSEC,
            Area = AreaForKind(HealthCheckType.DNSSEC),
            Subject = analysis.Subject ?? string.Empty,
            AuthenticData = analysis.AuthenticData,
            DsAuthenticData = analysis.DsAuthenticData,
            DsMatch = analysis.DsMatch,
            ChainValid = analysis.ChainValid,
            RootAnchorExpiration = analysis.RootAnchorExpiration,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"chain {(analysis.ChainValid ? "valid" : "invalid")}; DS {(analysis.DsMatch ? "match" : "check")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4035" },
            Raw = analysis
        };
    }
}

/// <summary>Provides dnssec status info functionality.</summary>
public class DnssecStatusInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the authentic data value.</summary>
    public bool AuthenticData { get; set; }
    /// <summary>Gets or sets the ds authentic data value.</summary>
    public bool DsAuthenticData { get; set; }
    /// <summary>Gets or sets the ds match value.</summary>
    public bool DsMatch { get; set; }
    /// <summary>Gets or sets the chain valid value.</summary>
    public bool ChainValid { get; set; }
    /// <summary>Gets or sets the root anchor expiration value.</summary>
    public System.DateTimeOffset? RootAnchorExpiration { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public DnsSecAnalysis Raw { get; set; } = new DnsSecAnalysis();
}
