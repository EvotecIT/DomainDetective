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
        return new PortScanInfo
        {
            Check = "PortScan",
            Subject = null,
            TotalChecked = total,
            OpenTcpCount = openTcp,
            OpenUdpCount = openUdp,
            Results = analysis.Results
        };
    }
}

public class PortScanInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenTcpCount { get; set; }
    public int OpenUdpCount { get; set; }
    public IReadOnlyDictionary<int, PortScanAnalysis.ScanResult> Results { get; set; }
}

