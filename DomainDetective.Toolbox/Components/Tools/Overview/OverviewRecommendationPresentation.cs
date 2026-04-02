using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class OverviewRecommendationPresentation
{
    public static IReadOnlyList<DomainOverviewDetailCardView> BuildProblemCards(IReadOnlyList<RecommendationAdvice>? items, int take = 6)
    {
        if (items == null || items.Count == 0 || take <= 0)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return items
            .Take(take)
            .Select(static item => BuildCard(item, isPositive: false))
            .ToArray();
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildPositiveCards(IReadOnlyList<RecommendationAdvice>? items, int take = 6)
    {
        if (items == null || items.Count == 0 || take <= 0)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return items
            .Take(take)
            .Select(static item => BuildCard(item, isPositive: true))
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildCard(RecommendationAdvice advice, bool isPositive)
    {
        var tags = new List<string>();

        var domainTag = FormatDomainTag(advice.Domain);
        if (!string.IsNullOrWhiteSpace(domainTag))
        {
            tags.Add(domainTag);
        }

        if (isPositive)
        {
            tags.Add("Keep in place");
        }
        else
        {
            tags.Add("Effort: " + advice.Effort);
        }

        if (!isPositive && !string.IsNullOrWhiteSpace(advice.Impact))
        {
            tags.Add("Impact: " + advice.Impact);
        }

        if (advice.Tags.Count > 0)
        {
            tags.AddRange(advice.Tags
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(3));
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(advice.How))
        {
            samples.Add("How: " + advice.How);
        }

        if (!string.IsNullOrWhiteSpace(advice.Verify))
        {
            samples.Add("Verify: " + advice.Verify);
        }

        if (advice.Links.Count > 0)
        {
            samples.AddRange(advice.Links
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(2)
                .Select(static value => "Reference: " + value));
        }

        return new DomainOverviewDetailCardView
        {
            Title = advice.Title,
            ValueLabel = FormatValueLabel(advice, isPositive),
            Summary = string.IsNullOrWhiteSpace(advice.Why)
                ? isPositive
                    ? "DD confirmed this as a positive posture signal."
                    : "DD identified this as a posture item worth tracking."
                : advice.Why,
            Tags = tags.Where(static value => !string.IsNullOrWhiteSpace(value)).ToArray(),
            Samples = samples.Where(static value => !string.IsNullOrWhiteSpace(value)).ToArray()
        };
    }

    private static string FormatDomain(RecommendationDomain domain)
    {
        return domain switch
        {
            RecommendationDomain.EmailAuth => "Email auth",
            RecommendationDomain.ThreatIntel => "Threat intel",
            RecommendationDomain.Other => string.Empty,
            _ => domain.ToString()
        };
    }

    private static string? FormatDomainTag(RecommendationDomain domain)
    {
        var formatted = FormatDomain(domain);
        return string.IsNullOrWhiteSpace(formatted) ? null : "Area: " + formatted;
    }

    private static string FormatValueLabel(RecommendationAdvice advice, bool isPositive)
    {
        if (isPositive)
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(advice.Impact))
        {
            return advice.Impact;
        }

        return advice.Effort + " effort";
    }
}
