using System;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    public static AgentReadinessSection? BuildAgentReadiness(DomainDetective.Views.AgentReadinessInfo agent)
    {
        if (agent == null) return null;

        var markdownAvailable = agent.MarkdownDirect || !string.IsNullOrWhiteSpace(agent.MarkdownAlternateUrl);
        var section = new AgentReadinessSection
        {
            Status = string.IsNullOrWhiteSpace(agent.Status) ? "-" : agent.Status,
            Score = agent.Score,
            RobotsPresent = agent.RobotsPresent,
            SitemapCount = agent.SitemapCount,
            LlmsTxtPresent = agent.LlmsTxtPresent,
            MarkdownAvailable = markdownAvailable,
            MarkdownAlternateUrl = agent.MarkdownAlternateUrl,
            Origin = agent.Origin,
            MainPageUrl = agent.MainPageUrl,
            WarningCount = agent.WarningCount,
            ErrorCount = agent.ErrorCount
        };

        section.Summary.Add(("Status", section.Status));
        section.Summary.Add(("Score", agent.Score.ToString("0.##", CultureInfo.InvariantCulture)));
        if (!string.IsNullOrWhiteSpace(agent.Origin)) section.Summary.Add(("Origin", agent.Origin!));
        if (!string.IsNullOrWhiteSpace(agent.MainPageUrl)) section.Summary.Add(("Main Page", agent.MainPageUrl!));
        section.Summary.Add(("robots.txt", agent.RobotsPresent ? "Present" : "Missing"));
        section.Summary.Add(("Sitemaps", agent.SitemapCount.ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("llms.txt", agent.LlmsTxtPresent ? "Present" : "Missing"));
        section.Summary.Add(("Markdown", agent.MarkdownDirect ? "Direct" : (!string.IsNullOrWhiteSpace(agent.MarkdownAlternateUrl) ? "Alternate" : "Missing")));
        section.Summary.Add(("Content Signals", (agent.ContentSignals?.Length ?? 0).ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Link Relations", (agent.LinkRelations?.Length ?? 0).ToString(CultureInfo.InvariantCulture)));
        section.Summary.Add(("Endpoint Probes", (agent.EndpointProbes?.Length ?? 0).ToString(CultureInfo.InvariantCulture)));

        foreach (var category in agent.CategoryScores ?? Array.Empty<AgentReadinessCategoryScore>())
        {
            if (category == null) continue;
            section.Categories.Add(new AgentReadinessSection.CategoryRow
            {
                Category = category.Category,
                Score = category.Score,
                MaxScore = category.MaxScore,
                WeightedScore = category.WeightedScore,
                Weight = category.Weight,
                Passed = category.Passed,
                Warnings = category.Warnings,
                Failed = category.Failed
            });
        }

        foreach (var check in agent.Checks ?? Array.Empty<AgentReadinessCheck>())
        {
            if (check == null) continue;
            section.Checks.Add(new AgentReadinessSection.CheckRow
            {
                Id = check.Id,
                Category = check.Category,
                Name = check.Name,
                Status = check.Status.ToString(),
                Score = check.Score,
                MaxScore = check.MaxScore,
                Evidence = check.Evidence,
                Code = check.Code
            });
        }

        foreach (var endpoint in agent.EndpointProbes ?? Array.Empty<AgentReadinessEndpointProbe>())
        {
            if (endpoint == null) continue;
            section.Endpoints.Add(new AgentReadinessSection.EndpointRow
            {
                Kind = endpoint.Kind,
                Url = endpoint.Url,
                StatusCode = endpoint.StatusCode,
                ContentType = endpoint.ContentType ?? string.Empty,
                Present = endpoint.Present,
                ValidJson = endpoint.ValidJson,
                ShapeValid = endpoint.ShapeValid,
                Shape = endpoint.Shape ?? string.Empty,
                DiscoverySource = endpoint.DiscoverySource,
                Error = endpoint.Error ?? string.Empty
            });
        }

        foreach (var link in agent.LinkRelations ?? Array.Empty<AgentReadinessLinkRelation>())
        {
            if (link == null) continue;
            section.Links.Add(new AgentReadinessSection.LinkRow
            {
                Relation = link.Relation,
                Target = link.Target,
                Type = link.Type ?? string.Empty,
                SourceUrl = link.SourceUrl
            });
        }

        foreach (var signal in agent.ContentSignals ?? Array.Empty<ContentSignalPolicy>())
        {
            if (signal == null) continue;
            section.ContentSignals.Add(new AgentReadinessSection.ContentSignalRow
            {
                Source = signal.Source,
                Search = signal.Search ?? string.Empty,
                AiInput = signal.AiInput ?? string.Empty,
                AiTrain = signal.AiTrain ?? string.Empty,
                RawValue = signal.RawValue
            });
        }

        foreach (var assessment in (agent.Assessments ?? Array.Empty<Assessment>()).Where(a => a != null && a.Severity != AssessmentSeverity.Info))
        {
            section.Findings.Add(new SimpleFinding(
                assessment.Severity.ToString(),
                assessment.Code ?? string.Empty,
                assessment.Target ?? string.Empty,
                assessment.Message ?? string.Empty));
        }

        foreach (var positive in agent.Positives ?? Array.Empty<RecommendationAdvice>())
        {
            var text = positive?.Title ?? positive?.Code;
            if (!string.IsNullOrWhiteSpace(text)) section.Positives.Add(text!);
        }

        foreach (var reference in agent.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(reference)) section.References.Add(reference);
        }

        try
        {
            foreach (var highlight in agent.Narrative.Highlights?.AsEnumerable() ?? Enumerable.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(highlight)) section.Highlights.Add(highlight);
            }
        }
        catch
        {
        }

        return section;
    }
}
