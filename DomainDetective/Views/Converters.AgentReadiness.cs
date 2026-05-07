using System;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Converts agent readiness analysis to a view model.</summary>
    public static AgentReadinessInfo Convert(AgentReadinessAnalysis analysis) {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new AgentReadinessInfo {
            Check = HealthCheckType.AGENTREADINESS,
            Area = AreaForKind(HealthCheckType.AGENTREADINESS),
            Subject = analysis.Subject,
            Origin = analysis.OriginUri?.AbsoluteUri,
            MainPageUrl = analysis.MainPageUrl,
            Score = analysis.Score,
            RobotsPresent = analysis.RobotsPresent,
            SitemapCount = analysis.Robots?.Sitemaps.Count ?? 0,
            LlmsTxtPresent = analysis.EndpointProbes.Any(probe => probe.Kind.Equals("llms.txt", StringComparison.OrdinalIgnoreCase) && probe.Present),
            MarkdownDirect = analysis.Markdown.DirectMarkdown,
            MarkdownAlternateUrl = analysis.Markdown.AlternateMarkdownUrl,
            TrustHeaderCount = analysis.TrustHeaderCount,
            TrustHeaderTotal = analysis.TrustHeaderTotal,
            ContentSignals = analysis.ContentSignals.ToArray(),
            LinkRelations = analysis.LinkRelations.ToArray(),
            EndpointProbes = analysis.EndpointProbes.ToArray(),
            Checks = analysis.Checks.ToArray(),
            CategoryScores = analysis.CategoryScores.ToArray(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            Positives = positives,
            Narrative = DomainDetective.Narratives.AgentReadinessNarrative.Build(analysis),
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model for AI crawler and agent readiness.
/// </summary>
public sealed class AgentReadinessInfo {
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the origin value.</summary>
    public string? Origin { get; set; }
    /// <summary>Gets or sets the main page URL.</summary>
    public string? MainPageUrl { get; set; }
    /// <summary>Gets or sets the score value.</summary>
    public double Score { get; set; }
    /// <summary>Gets or sets a value indicating whether robots.txt was present.</summary>
    public bool RobotsPresent { get; set; }
    /// <summary>Gets or sets the sitemap count value.</summary>
    public int SitemapCount { get; set; }
    /// <summary>Gets or sets a value indicating whether llms.txt was present.</summary>
    public bool LlmsTxtPresent { get; set; }
    /// <summary>Gets or sets a value indicating whether markdown was negotiated directly.</summary>
    public bool MarkdownDirect { get; set; }
    /// <summary>Gets or sets the markdown alternate URL.</summary>
    public string? MarkdownAlternateUrl { get; set; }
    /// <summary>Gets or sets the observed trust header count.</summary>
    public int TrustHeaderCount { get; set; }
    /// <summary>Gets or sets the total trust header count checked.</summary>
    public int TrustHeaderTotal { get; set; }
    /// <summary>Gets or sets the content signals value.</summary>
    public ContentSignalPolicy[] ContentSignals { get; set; } = Array.Empty<ContentSignalPolicy>();
    /// <summary>Gets or sets the link relations value.</summary>
    public AgentReadinessLinkRelation[] LinkRelations { get; set; } = Array.Empty<AgentReadinessLinkRelation>();
    /// <summary>Gets or sets the endpoint probes value.</summary>
    public AgentReadinessEndpointProbe[] EndpointProbes { get; set; } = Array.Empty<AgentReadinessEndpointProbe>();
    /// <summary>Gets or sets the checks value.</summary>
    public AgentReadinessCheck[] Checks { get; set; } = Array.Empty<AgentReadinessCheck>();
    /// <summary>Gets or sets the category scores value.</summary>
    public AgentReadinessCategoryScore[] CategoryScores { get; set; } = Array.Empty<AgentReadinessCategoryScore>();
    /// <summary>Gets or sets the assessments value.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.AgentReadinessNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.AgentReadinessNarrative.Sections();
    /// <summary>Gets or sets the references value.</summary>
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the composition section key.</summary>
    public string SectionKey { get; set; } = "Agent Readiness";
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public AgentReadinessAnalysis Raw { get; set; } = new AgentReadinessAnalysis();
}
