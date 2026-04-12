using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides robots txt narrative functionality.</summary>
public static class RobotsTxtNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(RobotsTxtAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var domainCandidate = analysis?.Domain;
        string subj;
        if (domainCandidate != null && !string.IsNullOrWhiteSpace(domainCandidate))
        {
            subj = domainCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"robots.txt Report — {subj}";
        var subtitle = "robots.txt Assessment";
        var category = "Web Crawling";
        var keywords = $"robots.txt, crawl, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "robots.txt guides crawlers on which paths to access.";
        var why = "Clear directives and sitemap references protect sensitive areas and improve indexing.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || !analysis.RecordPresent)
        {
            hi.Add("robots.txt not found.");
            return new Sections
            {
                Title = title,
                Subtitle = subtitle,
                Category = category,
                Keywords = keywords,
                Creator = creator,
                Introduction = intro,
                WhyItMatters = why,
                Highlights = hi,
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.FallbackUsed
            ? "robots.txt served over HTTP."
            : "robots.txt available over HTTPS.");

        var robots = analysis.Robots;
        if (robots != null)
        {
            var disallows = robots.Groups
                .SelectMany(g => g.Directives)
                .Where(d => d.Type == RobotsDirectiveType.Disallow)
                .Select(d => d.Value)
                .ToList();
            if (disallows.Count > 0)
            {
                hi.Add($"Disallow rules: {disallows.Count}.");
                det.AddRange(disallows.Select(d => $"Disallow: {d}"));
            }

            if (robots.Sitemaps.Count > 0)
            {
                hi.Add($"Sitemaps referenced: {robots.Sitemaps.Count}.");
                det.AddRange(robots.Sitemaps.Select(s => $"Sitemap: {s}"));
            }
        }

        var refs = DefaultRefs();
        try
        {
            if (assessments != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
            }
        }
        catch (Exception ex)
        {
            analysis?.Logger?.WriteDebug("Failed to split assessments: {0}", ex.Message);
        }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://developers.google.com/search/docs/crawling-indexing/robots/intro",
        "https://www.robotstxt.org/robotstxt.html"
    };
}

