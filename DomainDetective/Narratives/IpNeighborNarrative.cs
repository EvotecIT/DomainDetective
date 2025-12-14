using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives
{
    public static class IpNeighborNarrative
    {
        public sealed class Sections : NarrativeSections { }

        public static Sections Build(IPNeighborAnalysis? analysis)
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
            var title = $"IP Neighbor Report — {subj}";
            var subtitle = "IP Neighbor Analysis";
            var category = "Infrastructure";
            var keywords = $"ip neighbors, passive dns, co-hosting, DomainDetective, {subj}";
            var creator = "DomainDetective";
            var intro = "Neighbor analysis enumerates domains sharing the same IP using PTR and passive DNS.";
            var why = "Shared addresses can indicate virtual hosting or potential reputation bleed.";

            var hi = new List<string>();
            var det = new List<string>();
            var positives = new List<string>();
        var negatives = new List<string>();
            var remediations = new List<string>();

            foreach (var r in analysis?.Results ?? new List<IPNeighborResult>())
            {
                hi.Add($"{r.IpAddress} ({r.Type}) hosts {r.CoHostCount} domains — {r.Category} overlap");
                var doms = string.Join(", ", r.Domains.Take(5));
                if (r.Domains.Count > 5)
                {
                    doms += ", ...";
                }
                det.Add($"{r.IpAddress} RPKI {(r.RPKIValid ? "valid" : "invalid")}; {doms}");
            }

            var refs = new List<string>
            {
                "https://en.wikipedia.org/wiki/Passive_DNS",
                "https://stat.ripe.net/"
            };

            try
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>());
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
    }
}

