using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static IpNeighborInfo Convert(IPNeighborAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var addrCount = analysis.Results?.Count ?? 0;
        var totalDomains = analysis.Results?.Sum(r => r.Domains?.Count ?? 0) ?? 0;
        var mxCount = analysis.Results?.Count(r => string.Equals(r.Type, "MX", System.StringComparison.OrdinalIgnoreCase)) ?? 0;
        var apexCount = addrCount - mxCount;
        return new IpNeighborInfo
        {
            Check = HealthCheckType.IPNEIGHBOR,
            Area = AreaForKind(HealthCheckType.IPNEIGHBOR),
            Subject = analysis.Subject,
            AddressCount = addrCount,
            TotalNeighborDomains = totalDomains,
            Results = analysis.Results ?? new List<IPNeighborResult>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"ips {addrCount} (apex {apexCount}/mx {mxCount}); domains {totalDomains}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class IpNeighborInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int AddressCount { get; set; }
    public int TotalNeighborDomains { get; set; }
    public IReadOnlyList<IPNeighborResult> Results { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public IPNeighborAnalysis Raw { get; set; } = null!;
}
