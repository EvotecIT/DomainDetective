using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

/// <summary>Tone of an overview verdict, used for colour and wording.</summary>
public enum OverviewVerdictTone {
    /// <summary>Not enough evidence for a verdict yet.</summary>
    Unknown,
    /// <summary>Every assessed control passed.</summary>
    Healthy,
    /// <summary>No failures, but some controls need review.</summary>
    Review,
    /// <summary>At least one control failed.</summary>
    Action
}

/// <summary>One item in the "fix these first" list of an overview verdict.</summary>
public sealed record OverviewFixItem(string Title, string Why, string How, string Severity, string? ToolSlug, string? Meta);

/// <summary>The summary shown at the top of a domain or tenant overview.</summary>
public sealed record OverviewVerdictView(
    OverviewVerdictTone Tone,
    string Headline,
    string Summary,
    int Passed,
    int Review,
    int Failed,
    int Other,
    IReadOnlyList<OverviewFixItem> FixFirst,
    IReadOnlyList<AggregateCheckStatusInfo> Healthy,
    IReadOnlyList<string> NotChecked) {
    /// <summary>Total number of controls with a definite state.</summary>
    public int Assessed => Passed + Review + Failed;
}

/// <summary>
/// Turns the overview controls and recommendations into a verdict, a short "fix these first" list and the passing
/// controls. Kept separate from the component so the prioritisation can be tested.
/// </summary>
public static class OverviewVerdictPresentation {
    private static readonly Dictionary<string, string> ToolSlugByKey = new(StringComparer.OrdinalIgnoreCase) {
        ["spf"] = "spf",
        ["dkim"] = "dkim",
        ["dmarc"] = "dmarc",
        ["mx"] = "mx",
        ["mta-sts"] = "mta-sts",
        ["tls-rpt"] = "tls-rpt",
        ["bimi"] = "bimi",
        ["dnssec"] = "dnssec",
        ["soa"] = "soa",
        ["caa"] = "caa",
        ["dane"] = "dane",
        ["cert"] = "cert-check",
        ["http"] = "http-headers",
        ["security-txt"] = "security-txt",
        ["rdap"] = "rdap",
        ["dnsbl"] = "dnsbl",
        ["subdomains"] = "ct-subdomains"
    };

    // Order of importance inside each severity: core authentication and delivery before optional hardening.
    private static readonly string[] ImportanceOrder = {
        "dmarc", "spf", "dkim", "mx", "cert", "dnssec", "http", "dnsbl", "caa", "mta-sts", "tls-rpt", "security-txt",
        "soa", "rdap", "subdomains", "dane", "bimi"
    };

    /// <summary>Builds the verdict for a set of overview controls and recommendations.</summary>
    /// <param name="subject">Domain or tenant shown in the headline.</param>
    /// <param name="checks">Controls from every overview section.</param>
    /// <param name="recommendations">Prioritised remediation advice, most important first.</param>
    /// <param name="take">Maximum number of fix-first items.</param>
    /// <param name="notChecked">Sections this run could not assess (for example in the browser edition); their
    /// controls must already be left out of <paramref name="checks"/> so they do not count as failures.</param>
    public static OverviewVerdictView Build(
        string? subject,
        IEnumerable<AggregateCheckStatusInfo>? checks,
        IEnumerable<RecommendationAdvice>? recommendations,
        int take = 3,
        IEnumerable<string>? notChecked = null) {
        var all = (checks ?? Array.Empty<AggregateCheckStatusInfo>()).Where(static check => check is not null).ToList();
        var failed = all.Where(static check => check.State == AggregateCheckState.Fail).OrderBy(static check => Importance(check.Key)).ToList();
        var review = all.Where(static check => check.State == AggregateCheckState.Warning).OrderBy(static check => Importance(check.Key)).ToList();
        var passed = all.Where(static check => check.State == AggregateCheckState.Pass).ToList();
        var other = all.Count - failed.Count - review.Count - passed.Count;
        var name = string.IsNullOrWhiteSpace(subject) ? "This domain" : subject!.Trim();

        OverviewVerdictTone tone;
        string headline;
        if (failed.Count > 0) {
            tone = OverviewVerdictTone.Action;
            headline = "Action needed";
        } else if (review.Count > 0) {
            tone = OverviewVerdictTone.Review;
            headline = "Mostly healthy";
        } else if (passed.Count > 0) {
            tone = OverviewVerdictTone.Healthy;
            headline = "Healthy";
        } else {
            tone = OverviewVerdictTone.Unknown;
            headline = "Not enough evidence yet";
        }

        var summary = tone switch {
            OverviewVerdictTone.Action => $"{name} has {Count(failed.Count, "failing control")}{(review.Count > 0 ? " and " + Count(review.Count, "control") + " to review" : string.Empty)} across {Count(passed.Count + review.Count + failed.Count, "assessed control")}.",
            OverviewVerdictTone.Review => $"Nothing on {name} is failing, but {Count(review.Count, "control")} could be stronger.",
            OverviewVerdictTone.Healthy => $"All {Count(passed.Count, "assessed control")} on {name} passed.",
            _ => $"DomainDetective has not assessed enough controls on {name} to give a verdict."
        };

        var fixes = BuildFixFirst(failed, review, recommendations, take);
        var skipped = (notChecked ?? Array.Empty<string>())
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return new OverviewVerdictView(tone, headline, summary, passed.Count, review.Count, failed.Count, other, fixes, passed, skipped);
    }

    /// <summary>Maps an overview control key or recommendation area to the tool that checks it in depth.</summary>
    public static string? ResolveToolSlug(string? key) {
        if (string.IsNullOrWhiteSpace(key)) {
            return null;
        }

        return ToolSlugByKey.TryGetValue(key.Trim(), out var slug) ? slug : null;
    }

    private static IReadOnlyList<OverviewFixItem> BuildFixFirst(
        IReadOnlyList<AggregateCheckStatusInfo> failed,
        IReadOnlyList<AggregateCheckStatusInfo> review,
        IEnumerable<RecommendationAdvice>? recommendations,
        int take) {
        if (take <= 0) {
            return Array.Empty<OverviewFixItem>();
        }

        var items = new List<OverviewFixItem>();
        var coveredSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Failing controls come first: they are the concrete breakages. Matching advice supplies the "how".
        var advice = (recommendations ?? Array.Empty<RecommendationAdvice>()).Where(static item => item is not null).ToList();
        foreach (var check in failed.Concat(review)) {
            if (items.Count >= take) {
                break;
            }

            var slug = ResolveToolSlug(check.Key);
            var match = advice.FirstOrDefault(item => slug is not null && string.Equals(ResolveAdviceSlug(item), slug, StringComparison.OrdinalIgnoreCase));
            var severity = check.State == AggregateCheckState.Fail ? "fail" : "warn";
            var why = FirstNonEmpty(match?.Why, check.Detail, check.Value);
            var how = FirstNonEmpty(match?.How, string.Empty);
            var title = string.IsNullOrWhiteSpace(check.Value)
                ? check.Label
                : $"{check.Label}: {check.Value}";
            items.Add(new OverviewFixItem(title, why, how, severity, slug, BuildMeta(match)));
            if (slug is not null) {
                coveredSlugs.Add(slug);
            }
        }

        // Then the remaining advice, in the order the engine prioritised it.
        foreach (var item in advice) {
            if (items.Count >= take) {
                break;
            }

            var slug = ResolveAdviceSlug(item);
            if (slug is not null && coveredSlugs.Contains(slug)) {
                continue;
            }

            items.Add(new OverviewFixItem(item.Title, item.Why, item.How, "warn", slug, BuildMeta(item)));
            if (slug is not null) {
                coveredSlugs.Add(slug);
            }
        }

        return items;
    }

    private static readonly (string Keyword, string Slug)[] AdviceKeywords = {
        ("mta-sts", "mta-sts"), ("mtasts", "mta-sts"), ("tls-rpt", "tls-rpt"), ("tlsrpt", "tls-rpt"),
        ("security.txt", "security-txt"), ("securitytxt", "security-txt"), ("dnssec", "dnssec"), ("dane", "dane"),
        ("caa", "caa"), ("bimi", "bimi"), ("dmarc", "dmarc"), ("dkim", "dkim"), ("spf", "spf"), ("dnsbl", "dnsbl"),
        ("blocklist", "dnsbl"), ("certificate", "cert-check"), ("rdap", "rdap"), ("whois", "rdap"), ("header", "http-headers"),
        ("hsts", "http-headers"), ("mx", "mx")
    };

    private static string? ResolveAdviceSlug(RecommendationAdvice advice) {
        // Specific protocol names in the code or title win over the broad area: MTA-STS advice is filed under TLS.
        var text = ((advice.Code ?? string.Empty) + " " + (advice.Title ?? string.Empty)).ToLowerInvariant();
        foreach (var (keyword, slug) in AdviceKeywords) {
            if (ContainsWord(text, keyword)) {
                return slug;
            }
        }

        return advice.Domain switch {
            RecommendationDomain.Spf => "spf",
            RecommendationDomain.Dkim => "dkim",
            RecommendationDomain.Dmarc => "dmarc",
            RecommendationDomain.Dnssec => "dnssec",
            RecommendationDomain.Http => "http-headers",
            RecommendationDomain.Tls => "cert-check",
            RecommendationDomain.ThreatIntel => "dnsbl",
            RecommendationDomain.Branding => "bimi",
            _ => null
        };
    }

    private static bool ContainsWord(string text, string keyword) {
        var index = text.IndexOf(keyword, StringComparison.Ordinal);
        while (index >= 0) {
            var before = index == 0 || !char.IsLetterOrDigit(text[index - 1]);
            var afterIndex = index + keyword.Length;
            var after = afterIndex >= text.Length || !char.IsLetterOrDigit(text[afterIndex]);
            if (before && after) {
                return true;
            }

            index = text.IndexOf(keyword, index + 1, StringComparison.Ordinal);
        }

        return false;
    }

    private static string? BuildMeta(RecommendationAdvice? advice) {
        if (advice is null) {
            return null;
        }

        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(advice.Impact)) {
            parts.Add("Impact: " + advice.Impact);
        }

        parts.Add("Effort: " + advice.Effort.ToString().ToLowerInvariant());
        return string.Join(" · ", parts);
    }

    private static string FirstNonEmpty(params string?[] values) {
        foreach (var value in values) {
            if (!string.IsNullOrWhiteSpace(value)) {
                return value!.Trim();
            }
        }

        return string.Empty;
    }

    private static int Importance(string? key) {
        var index = Array.FindIndex(ImportanceOrder, item => string.Equals(item, key, StringComparison.OrdinalIgnoreCase));
        return index < 0 ? ImportanceOrder.Length : index;
    }

    private static string Count(int count, string noun) => count == 1 ? $"1 {noun}" : $"{count} {noun}s";
}
