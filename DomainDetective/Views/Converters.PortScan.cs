using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static PortScanInfo Convert(PortScanAnalysis analysis)
    {
        var total = analysis.Results?.Count ?? 0;
        var openTcp = analysis.Results?.Count(kv => kv.Value.TcpOpen) ?? 0;
        var openUdp = analysis.Results?.Count(kv => kv.Value.UdpOpen) ?? 0;
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var refs = BuildReferences(new List<StandardReference>(), recs);
        return new PortScanInfo
        {
            Check = HealthCheckType.PORTSCAN,
            Area = AreaForKind(HealthCheckType.PORTSCAN),
            Subject = analysis.Subject,
            TotalChecked = total,
            OpenTcpCount = openTcp,
            OpenUdpCount = openUdp,
            Results = analysis.Results ?? new Dictionary<int, PortScanAnalysis.ScanResult>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open TCP {openTcp}, UDP {openUdp} of {total}",
            Recommendations = recs,
            Positives = positives,
            References = refs,
            Raw = analysis
        };
    }
}

/// <summary>Provides port scan info functionality.</summary>
public class PortScanInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the open tcp count value.</summary>
    public int OpenTcpCount { get; set; }
    /// <summary>Gets or sets the open udp count value.</summary>
    public int OpenUdpCount { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyDictionary<int, PortScanAnalysis.ScanResult> Results { get; set; } = null!;
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
    public PortScanAnalysis Raw { get; set; } = null!;
}
