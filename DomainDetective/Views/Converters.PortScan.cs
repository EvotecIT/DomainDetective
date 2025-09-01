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
        var recs = RecommendationEngine.From(assessments);
        var refs = BuildReferences(new List<StandardReference>(), recs);
        return new PortScanInfo
        {
            Check = "PORTSCAN",
            Area = AreaFor("PORTSCAN"),
            Subject = null,
            TotalChecked = total,
            OpenTcpCount = openTcp,
            OpenUdpCount = openUdp,
            Results = analysis.Results,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"open TCP {openTcp}, UDP {openUdp} of {total}",
            Recommendations = recs,
            References = refs,
            Raw = analysis
        };
    }
}

public class PortScanInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenTcpCount { get; set; }
    public int OpenUdpCount { get; set; }
    public IReadOnlyDictionary<int, PortScanAnalysis.ScanResult> Results { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public PortScanAnalysis Raw { get; set; }
}
