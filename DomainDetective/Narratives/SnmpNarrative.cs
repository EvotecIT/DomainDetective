using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class SnmpNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(SnmpAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(host)" : analysis.Subject!;
        var title = $"SNMP Report — {subj}";
        var subtitle = "SNMP Exposure Assessment";
        var category = "Infrastructure";
        var keywords = $"SNMP, network management, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SNMP probes test for unauthenticated responses on the default community string.";
        var why = "Open SNMP services can leak sensitive network information and be abused for reflection attacks.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        foreach (var kv in analysis?.ServerResults ?? new Dictionary<string, bool>())
        {
            hi.Add(kv.Value
                ? $"{kv.Key} responded to SNMP probe."
                : $"{kv.Key} did not respond to SNMP probe.");
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc1157"
        };

        try
        {
            var assess = assessments ?? analysis?.Assessments ?? new List<Assessment>();
            AssessmentSplit.SplitTitles(assess, out positives, out remediations);
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
            Remediations = remediations
        };
    }
}

