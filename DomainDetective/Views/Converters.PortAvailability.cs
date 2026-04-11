using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides port availability info functionality.</summary>
public class PortAvailabilityInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the open count value.</summary>
    public int OpenCount { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyDictionary<string, PortAvailabilityAnalysis.PortResult> Results { get; set; } = null!;
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
}
