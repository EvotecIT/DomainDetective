using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static RdapInfo Convert(RdapAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new RdapInfo
        {
            Check = HealthCheckType.RDAP,
            Area = AreaForKind(HealthCheckType.RDAP),
            Subject = analysis.DomainName,
            Registrar = analysis.Registrar,
            RegistrarId = analysis.RegistrarId,
            CreationDate = analysis.CreationDate,
            ExpiryDate = analysis.ExpiryDate,
            NameServers = analysis.NameServers,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"registrar {(analysis.Registrar ?? "?")}; expires {analysis.ExpiryDate ?? "?"}",
            Assessments = analysis.Assessments,
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc7483" },
            Raw = analysis
        };
    }
}

public class RdapInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public string? Registrar { get; set; }
    public string? RegistrarId { get; set; }
    public string? CreationDate { get; set; }
    public string? ExpiryDate { get; set; }
    public IReadOnlyList<string> NameServers { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public RdapAnalysis Raw { get; set; } = null!;
}
