using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides arc info functionality.</summary>
public class ArcInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the arc headers found value.</summary>
    public bool ArcHeadersFound { get; set; }
    /// <summary>Gets or sets the seal count value.</summary>
    public int SealCount { get; set; }
    /// <summary>Gets or sets the aar count value.</summary>
    public int AarCount { get; set; }
    /// <summary>Gets or sets the seals include signatures value.</summary>
    public bool SealsIncludeSignatures { get; set; }
    /// <summary>Gets or sets the valid chain value.</summary>
    public bool ValidChain { get; set; }
    /// <summary>Gets or sets the chain state value.</summary>
    public string ChainState { get; set; } = null!;
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
    public DomainDetective.ARCAnalysis Raw { get; set; } = null!;
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.ArcNarrative.Sections Narrative { get; set; } = null!;
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = null!;
}
