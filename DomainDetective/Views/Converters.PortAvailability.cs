using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static PortAvailabilityInfo Convert(PortAvailabilityAnalysis analysis)
    {
        int total = analysis.ServerResults != null ? analysis.ServerResults.Count : 0;
        int open = 0;
        if (analysis.ServerResults != null)
        {
            foreach (var r in analysis.ServerResults.Values)
            {
                if (r != null && r.Success) open++;
            }
        }
        string? subject = null;
        if (analysis.ServerResults != null && analysis.ServerResults.Count == 1)
        {
            foreach (var key in analysis.ServerResults.Keys) { subject = key; break; }
        }
        return new PortAvailabilityInfo
        {
            Check = HealthCheckType.PORTAVAILABILITY,
            Area = AreaForKind(HealthCheckType.PORTAVAILABILITY),
            Subject = subject,
            TotalChecked = total,
            OpenCount = open,
            Results = analysis.ServerResults ?? new Dictionary<string, PortAvailabilityAnalysis.PortResult>(),
            Summary = $"open {open}/{total}"
        };
    }
}

public class PortAvailabilityInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenCount { get; set; }
    public IReadOnlyDictionary<string, PortAvailabilityAnalysis.PortResult> Results { get; set; } = null!;
    public string Summary { get; set; } = null!;
}
