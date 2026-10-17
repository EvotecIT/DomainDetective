using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides ns narrative functionality.</summary>
public static class NSNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(NSAnalysis ns)
    {
        var subj = string.IsNullOrWhiteSpace(ns.Subject) ? "(domain)" : ns.Subject;
        var title = $"Nameserver Report — {subj}";
        var subtitle = "Nameserver Assessment";
        var category = "DNS Infrastructure";
        var keywords = $"NS, DNS, infrastructure, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Authoritative nameservers publish DNS information and delegate zones to resolvers.";
        var why = "Healthy nameserver configuration improves availability, performance and security of DNS resolution.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        // Highlights
        if (!ns.NsLookupComplete) {
            hi.Add("NS record discovery could not be verified; record presence is unknown.");
        } else {
            hi.Add(ns.NsRecordExists
                ? $"NS records published: {ns.NsRecords.Count}"
                : "No NS records are published.");
            hi.Add(ns.AtLeastTwoRecords
                ? "At least two NS records present."
                : "Fewer than two NS records published.");
            if (ns.HasDuplicates) { hi.Add("Duplicate NS records detected."); }
            hi.Add(ns.AllHaveAOrAaaa
                ? "All NS hostnames have A/AAAA addresses."
                : !ns.AddressResultKnown ? "Some NS address lookups could not be verified." : "Some NS hostnames lack A/AAAA addresses.");
            hi.Add(ns.HasDiverseLocations
                ? "Nameservers are geographically diverse."
                : !ns.DiversityResultKnown ? "Nameserver diversity could not be fully verified." : "Nameservers lack geographic diversity.");
        }
        if (ns.GluePresenceKnown) {
            hi.Add(ns.GlueRecordsComplete
                ? "Parent zone provides glue records for in-bailiwick NS."
                : "Parent zone missing glue records for in-bailiwick NS.");
            hi.Add(ns.GlueConsistencyKnown
                ? ns.GlueRecordsConsistent ? "Parent glue records match child A/AAAA values."
                    : "Parent glue records differ from child A/AAAA values."
                : !ns.GlueRecordsComplete ? "Glue consistency cannot be verified until missing glue records are available."
                    : "Some parent glue comparisons could not be verified.");
            hi.Add(ns.DelegationMatches
                ? "Parent delegation matches child NS set."
                : "Parent delegation differs from child NS set.");
        } else {
            hi.Add("Parent delegation and glue have not been fully verified.");
        }

        // Details
        if (ns.NsRecords != null && ns.NsRecords.Count > 0)
            det.Add($"NS set: {string.Join(", ", ns.NsRecords)}");
        if (ns.ParentNsRecords != null && ns.ParentNsRecords.Count > 0)
            det.Add($"Parent NS set: {string.Join(", ", ns.ParentNsRecords)}");
        if (ns.NsLookupComplete && ns.DiversityResultKnown) {
            det.Add(ns.HasDiverseLocations
                ? "NS addresses span multiple networks/subnets."
                : "NS addresses share the same network.");
        }
        if (ns.GluePresenceKnown) {
            det.Add(ns.GlueRecordsComplete
                ? "Glue records are complete."
                : "Glue records are incomplete.");
            det.Add(!ns.GlueConsistencyKnown ? "Glue consistency remains unverified."
                : ns.GlueRecordsConsistent ? "Glue records are consistent with child zone."
                : "Glue records are inconsistent with child zone.");
        }
        det.AddRange(ns.DnsQueryErrors);
        if (!string.IsNullOrWhiteSpace(ns.Subject))
            det.Add($"Subject: {ns.Subject}");

        // References
        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc1912",
            "https://www.icann.org/resources/pages/glossary-2014-02-03-en#authoritativeserver"
        };

        // Assessments -> positives and remediations
        try
        {
            var assessments = (IEnumerable<Assessment>)(ns.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                string msg;
                var adviceTitle = g.Advice?.Title;
                if (adviceTitle == null || string.IsNullOrWhiteSpace(adviceTitle)) {
                    msg = g.Instances.FirstOrDefault()?.Message ?? g.Code;
                } else {
                    msg = adviceTitle;
                }
                if (g.MaxSeverity == AssessmentSeverity.Info)
                {
                    positives.Add(msg);
                }
                else
                {
                    negatives.Add(msg);
                    remediations.Add(msg);
                }
            }
        }
        catch { }

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
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
