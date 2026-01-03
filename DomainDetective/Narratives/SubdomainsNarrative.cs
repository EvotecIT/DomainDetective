using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class SubdomainsNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(SubdomainsAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var title = "Subdomain Discovery Report";
        var subtitle = "Certificate Transparency (CT) Inventory";
        var category = "DNS Discovery";
        var keywords = "subdomains, certificate transparency, CT, DNS, DomainDetective";
        var creator = "DomainDetective";

        var intro = "This check uses certificate transparency (CT) observations to discover hostnames that have appeared on publicly logged certificates.";
        var why = "CT can reveal historical or unintended subdomains (stale DNS, legacy services, shadow IT) that expand attack surface and should be reviewed.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Title = title,
                Subtitle = subtitle,
                Category = category,
                Keywords = keywords,
                Creator = creator,
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No subdomain discovery data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.QuerySucceeded ? "CT query succeeded." : "CT query failed.");
        if (analysis.QuerySucceeded)
        {
            hi.Add($"{analysis.Subdomains.Count} subdomain(s) discovered.");
            if (analysis.DistinctIssuerCount > 0)
            {
                hi.Add($"Issuer diversity: {analysis.DistinctIssuerCount}.");
            }
            if (analysis.FirstSeenUtc.HasValue || analysis.LastSeenUtc.HasValue)
            {
                var a = analysis.FirstSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                var b = analysis.LastSeenUtc?.ToString("yyyy-MM-dd") ?? "-";
                hi.Add($"Seen range (UTC): {a} .. {b}.");
            }
        }

        if (analysis.ResultsCapped)
        {
            hi.Add("CT processing was capped for performance.");
        }

        if (analysis.VerifyStillResolves)
        {
            hi.Add(analysis.ResolutionReduced ? "DNS verification was capped." : "DNS verification was performed.");
        }
        else
        {
            hi.Add("DNS verification was disabled.");
        }

        if (!string.IsNullOrWhiteSpace(analysis.FailureReason))
        {
            det.Add($"Failure reason: {analysis.FailureReason!.Trim()}");
        }
        det.Add($"CT rows observed: {analysis.CertificateObservationCount}.");
        if (analysis.ResultsCapped)
        {
            det.Add($"CT processing capped at {Math.Max(0, analysis.MaxCtRowsToProcess)} row(s) / {Math.Max(0, analysis.MaxSubdomains)} subdomain(s).");
        }

        if (analysis.Subdomains.Count > 0)
        {
            var statusCounts = analysis.Subdomains
                .GroupBy(s => s.ResolutionStatus)
                .ToDictionary(g => g.Key, g => g.Count());

            int Get(SubdomainResolutionStatus s) => statusCounts.TryGetValue(s, out var c) ? c : 0;
            det.Add($"DNS resolution: {Get(SubdomainResolutionStatus.Resolves)} resolves; {Get(SubdomainResolutionStatus.DoesNotResolve)} does not resolve; {Get(SubdomainResolutionStatus.QueryFailed)} query failed; {Get(SubdomainResolutionStatus.Unknown)} unknown.");
        }

        var refs = DefaultRefs();

        try
        {
            var assess = assessments ?? analysis.Assessments;
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assess);
        }
        catch
        {
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
        "https://www.rfc-editor.org/rfc/rfc6962"
    };
}
