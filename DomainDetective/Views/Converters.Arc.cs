using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static ArcInfo Convert(DomainDetective.ARCAnalysis analysis)
    {
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var narrative = DomainDetective.Narratives.ArcNarrative.Build(analysis);
        var sealCount = analysis.ArcSealHeaders?.Count ?? 0;
        var aarCount = analysis.ArcAuthenticationResultsHeaders?.Count ?? 0;
        var chain = analysis.ChainState.ToString();
        return new ArcInfo
        {
            Check = HealthCheckType.ARC,
            Area = AreaForKind(HealthCheckType.ARC),
            Subject = "Message Headers",
            ArcHeadersFound = analysis.ArcHeadersFound,
            SealCount = sealCount,
            AarCount = aarCount,
            SealsIncludeSignatures = analysis.SealsIncludeSignatures,
            ValidChain = analysis.ValidChain,
            ChainState = chain,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"headers {(analysis.ArcHeadersFound ? "present" : "missing")}; seals {sealCount}; aar {aarCount}; chain {chain}",
            Recommendations = recs,
            Positives = positives,
            // Static reference to ARC spec
            References = new [] { "https://datatracker.ietf.org/doc/html/rfc8617" },
            Raw = analysis,
            Narrative = narrative,
            Highlights = narrative.Highlights ?? new List<string>()
        };
    }
}

public class ArcInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public bool ArcHeadersFound { get; set; }
    public int SealCount { get; set; }
    public int AarCount { get; set; }
    public bool SealsIncludeSignatures { get; set; }
    public bool ValidChain { get; set; }
    public string ChainState { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DomainDetective.ARCAnalysis Raw { get; set; }
    public DomainDetective.Narratives.ArcNarrative.Sections Narrative { get; set; }
    public IReadOnlyList<string> Highlights { get; set; }
}
