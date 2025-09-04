using System.Collections.Generic;
using System;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class WhoisInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string WhoisServer { get; set; }
    public string LookupSource { get; set; }
    public string Registrar { get; set; }
    public string RegistrarId { get; set; }
    public string ExpiryDate { get; set; }
    public int? DaysUntilExpiration { get; set; }
    public bool ExpiresSoon { get; set; }
    public bool IsExpired { get; set; }
    public bool RegistrarLocked { get; set; }
    public bool PrivacyProtected { get; set; }
    public IReadOnlyList<string> NameServers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public WhoisAnalysis Raw { get; set; }
}
