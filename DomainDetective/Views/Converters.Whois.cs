using System.Collections.Generic;
using System;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static WhoisInfo Convert(WhoisAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        int? days = analysis.DaysUntilExpiration;
        bool? expiresSoon = analysis.ExpiresSoon;
        DateTimeOffset? expiry = null;
        if (DateTimeOffset.TryParse(analysis.ExpiryDate, out var d)) expiry = d;
        return new WhoisInfo
        {
            Check = HealthCheckType.WHOIS,
            Area = AreaForKind(HealthCheckType.WHOIS),
            Subject = analysis.DomainName,
            WhoisServer = analysis.WhoisServerUsed,
            LookupSource = analysis.WhoisLookupSource,
            Registrar = analysis.Registrar,
            RegistrarId = analysis.RegistrarId,
            ExpiryDate = analysis.ExpiryDate,
            DaysUntilExpiration = days,
            ExpiresSoon = analysis.ExpiresSoon,
            IsExpired = analysis.IsExpired,
            RegistrarLocked = analysis.RegistrarLocked,
            PrivacyProtected = analysis.PrivacyProtected,
            NameServers = analysis.NameServers,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"registrar {(analysis.Registrar ?? "?")}; {(analysis.IsExpired ? "expired" : (analysis.ExpiresSoon ? $"{days}d left" : "ok"))}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc3912" },
            Raw = analysis
        };
    }
}

/// <summary>Provides whois info functionality.</summary>
public class WhoisInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the whois server value.</summary>
    public string? WhoisServer { get; set; }
    /// <summary>Gets or sets the lookup source value.</summary>
    public string? LookupSource { get; set; }
    /// <summary>Gets or sets the registrar value.</summary>
    public string? Registrar { get; set; }
    /// <summary>Gets or sets the registrar id value.</summary>
    public string? RegistrarId { get; set; }
    /// <summary>Gets or sets the expiry date value.</summary>
    public string? ExpiryDate { get; set; }
    /// <summary>Gets or sets the days until expiration value.</summary>
    public int? DaysUntilExpiration { get; set; }
    /// <summary>Gets or sets the expires soon value.</summary>
    public bool ExpiresSoon { get; set; }
    /// <summary>Gets or sets the is expired value.</summary>
    public bool IsExpired { get; set; }
    /// <summary>Gets or sets the registrar locked value.</summary>
    public bool RegistrarLocked { get; set; }
    /// <summary>Gets or sets the privacy protected value.</summary>
    public bool PrivacyProtected { get; set; }
    /// <summary>Gets or sets the name servers value.</summary>
    public IReadOnlyList<string> NameServers { get; set; } = null!;
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
    /// <summary>Gets or sets the raw value.</summary>
    public WhoisAnalysis Raw { get; set; } = null!;
}
