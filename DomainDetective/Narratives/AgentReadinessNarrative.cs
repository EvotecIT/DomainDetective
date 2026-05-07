using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Builds narrative sections for agent readiness analysis.</summary>
public static class AgentReadinessNarrative {
    /// <summary>Agent readiness narrative sections.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Builds narrative content from an agent readiness analysis.</summary>
    public static Sections Build(AgentReadinessAnalysis? analysis) {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(site)" : analysis!.Subject;
        var title = $"Agent Readiness Report - {subj}";
        var subtitle = "AI crawler and agent discovery posture";
        var category = "Web Discovery";
        var keywords = $"agents, ai crawlers, llms.txt, robots.txt, API Catalog, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Agent readiness checks whether a website exposes clear, machine-readable resources for AI crawlers and agent workflows.";
        var why = "Explicit discovery resources reduce guesswork for agents and make site policy, content, APIs, and trust signals easier to verify.";

        var highlights = new List<string>();
        var details = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null) {
            highlights.Add("No agent readiness data available.");
        } else {
            highlights.Add($"Agent readiness score: {analysis.Score:0.##}/100.");

            if (analysis.RobotsPresent) {
                highlights.Add("robots.txt is present.");
            } else {
                highlights.Add("robots.txt was not found.");
            }

            if (analysis.Robots?.Sitemaps.Count > 0) {
                highlights.Add($"Sitemaps referenced: {analysis.Robots.Sitemaps.Count}.");
            }

            if (analysis.Markdown.DirectMarkdown) {
                highlights.Add("Direct Markdown negotiation is available.");
            } else if (!string.IsNullOrWhiteSpace(analysis.Markdown.AlternateMarkdownUrl)) {
                highlights.Add("Markdown alternate is discoverable.");
                details.Add($"Markdown alternate: {analysis.Markdown.AlternateMarkdownUrl}");
            } else {
                highlights.Add("Markdown representation was not discovered.");
            }

            if (analysis.ContentSignals.Count > 0) {
                highlights.Add("Content Signals policy is present.");
                details.AddRange(analysis.ContentSignals.Select(signal => $"Content-Signal ({signal.Source}): {signal.RawValue}"));
            }

            var presentEndpoints = analysis.EndpointProbes
                .Where(probe => probe.Present)
                .Select(probe => string.IsNullOrWhiteSpace(probe.Shape) ? probe.Kind : $"{probe.Kind} ({probe.Shape})")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (presentEndpoints.Length > 0) {
                highlights.Add($"Agent discovery endpoints found: {presentEndpoints.Length}.");
                details.Add("Discovery endpoints: " + string.Join(", ", presentEndpoints));
            }

            foreach (var categoryScore in analysis.CategoryScores.OrderBy(score => score.Category)) {
                details.Add($"{categoryScore.Category}: {categoryScore.Score:0.#}/{categoryScore.MaxScore:0.#} raw, {categoryScore.WeightedScore:0.##}/{categoryScore.Weight:0.##} weighted.");
            }

            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments);
        }

        return new Sections {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = highlights,
            Details = details,
            References = DefaultRefs(),
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new() {
        "https://www.rfc-editor.org/rfc/rfc9309",
        "https://www.rfc-editor.org/rfc/rfc8288",
        "https://www.rfc-editor.org/rfc/rfc9727.html",
        "https://www.rfc-editor.org/rfc/rfc8414",
        "https://www.ietf.org/rfc/rfc9728.html"
    };
}
