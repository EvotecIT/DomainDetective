using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class PortScanInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenTcpCount { get; set; }
    public int OpenUdpCount { get; set; }
    public IReadOnlyDictionary<int, PortScanAnalysis.ScanResult> Results { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public PortScanAnalysis Raw { get; set; } = null!;
}
