using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides edns narrative functionality.</summary>
public static class EdnsNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(EdnsSupportAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjCandidate = analysis?.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"EDNS Support Report — {subj}";
        var subtitle = "EDNS Assessment";
        var category = "DNS Infrastructure";
        var keywords = $"EDNS, DNS, infrastructure, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Extension Mechanisms for DNS (EDNS) extend DNS with larger UDP payloads and optional features like DNSSEC.";
        var why = "EDNS avoids truncated responses and enables modern DNS features such as DNSSEC.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.ServerSupport.Count == 0)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No EDNS data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        var total = analysis.ServerSupport.Count;
        var supported = analysis.ServerSupport.Values.Count(v => v.Supported);
        hi.Add($"{supported}/{total} servers support EDNS.");

        if (supported > 0)
        {
            var minSize = analysis.ServerSupport.Values.Where(v => v.Supported).Min(v => v.UdpPayloadSize);
            hi.Add($"Smallest advertised UDP size: {minSize} bytes.");

            var versions = analysis.ServerSupport.Values.Where(v => v.Supported).Select(v => v.Version).Distinct().ToList();
            if (versions.Count == 1 && versions[0] == 0)
            {
                hi.Add("All servers respond with EDNS version 0.");
            }
            else
            {
                hi.Add($"EDNS versions observed: {string.Join(", ", versions)}.");
            }
        }

        foreach (var kv in analysis.ServerSupport)
        {
            var info = kv.Value;
            if (info.Supported)
            {
                var line = $"{kv.Key}: UDP {info.UdpPayloadSize}, ver {info.Version}";
                if (info.TruncatedUdp) line += ", truncated";
                det.Add(line + ".");
            }
            else
            {
                det.Add($"{kv.Key}: no EDNS support.");
            }
        }

        var refs = DefaultRefs();

        try
        {
            var assess = assessments ?? analysis.Assessments ?? new List<Assessment>();
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
        "https://www.rfc-editor.org/rfc/rfc6891"
    };
}

