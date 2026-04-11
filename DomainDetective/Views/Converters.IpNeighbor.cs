using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides ip neighbor info functionality.</summary>
public class IpNeighborInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the address count value.</summary>
    public int AddressCount { get; set; }
    /// <summary>Gets or sets the total neighbor domains value.</summary>
    public int TotalNeighborDomains { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyList<IPNeighborResult> Results { get; set; } = null!;
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
    public IPNeighborAnalysis Raw { get; set; } = null!;
}
