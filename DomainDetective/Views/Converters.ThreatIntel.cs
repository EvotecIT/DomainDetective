using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ThreatIntelInfo Convert(ThreatIntelAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var findings = analysis.Listings?.Select(l => new ThreatListing { Source = l.Source.ToString(), Listed = l.IsListed }).ToList() ?? new List<ThreatListing>();
        var flagged = findings.Count(f => f.Listed);
        return new ThreatIntelInfo
        {
            Check = HealthCheckType.THREATINTEL,
            Area = AreaForKind(HealthCheckType.THREATINTEL),
            Subject = analysis.Subject,
            RiskScore = analysis.RiskScore,
            CompositeScore = analysis.CompositeScore,
            Severity = analysis.Severity,
            Confidence = analysis.Confidence,
            Listings = findings,
            FailureReason = analysis.FailureReason,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"Flagged by {flagged}/{findings.Count} providers; score {analysis.CompositeScore?.ToString() ?? "n/a"} ({analysis.Severity ?? "n/a"})",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://developers.google.com/safe-browsing", "https://www.virustotal.com/", "https://www.phishtank.com/", "https://urlhaus.abuse.ch/api/" },
            Raw = analysis
        };
    }
}

public class ThreatIntelInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int? RiskScore { get; set; }
    public int? CompositeScore { get; set; }
    public string? Severity { get; set; }
    public double? Confidence { get; set; }
    public IReadOnlyList<ThreatListing> Listings { get; set; } = null!;
    public string? FailureReason { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public ThreatIntelAnalysis Raw { get; set; } = null!;
}

public class ThreatListing
{
    public string Source { get; set; } = null!;
    public bool Listed { get; set; }
}

