using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ThreatIntelInfo Convert(ThreatIntelAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var findings = analysis.Listings?.Select(l => new ThreatListing { Source = l.Source.ToString(), Listed = l.IsListed }).ToList() ?? new List<ThreatListing>();
        var flagged = findings.Count(f => f.Listed);
        return new ThreatIntelInfo
        {
            Check = "THREATINTEL",
            Subject = analysis.Subject,
            RiskScore = analysis.RiskScore,
            Listings = findings,
            FailureReason = analysis.FailureReason,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"Flagged by {flagged}/{findings.Count} providers; RiskScore {analysis.RiskScore?.ToString() ?? "n/a"}",
            Recommendations = recs,
            References = new [] { "https://developers.google.com/safe-browsing", "https://www.virustotal.com/", "https://www.phishtank.com/", "https://urlhaus.abuse.ch/api/" },
            Raw = analysis
        };
    }
}

public class ThreatIntelInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public int? RiskScore { get; set; }
    public IReadOnlyList<ThreatListing> Listings { get; set; }
    public string FailureReason { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ThreatIntelAnalysis Raw { get; set; }
}

public class ThreatListing
{
    public string Source { get; set; }
    public bool Listed { get; set; }
}

