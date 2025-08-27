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
        return new PortAvailabilityInfo
        {
            Check = "PortAvailability",
            Subject = null,
            TotalChecked = total,
            OpenCount = open,
            Results = analysis.ServerResults
        };
    }
}

public class PortAvailabilityInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenCount { get; set; }
    public IReadOnlyDictionary<string, PortAvailabilityAnalysis.PortResult> Results { get; set; }
}
