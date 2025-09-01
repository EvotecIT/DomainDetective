using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static RdapInfo Convert(RdapAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
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
            References = new [] { "https://www.rfc-editor.org/rfc/rfc7483" },
            Raw = analysis
        };
    }
}

public class RdapInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string Registrar { get; set; }
    public string RegistrarId { get; set; }
    public string CreationDate { get; set; }
    public string ExpiryDate { get; set; }
    public IReadOnlyList<string> NameServers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public RdapAnalysis Raw { get; set; }
}
