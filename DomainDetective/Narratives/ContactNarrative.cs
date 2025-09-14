using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class ContactNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ContactInfoAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject;
        var title = $"Contact Record Report — {subj}";
        var subtitle = "Contact TXT Assessment";
        var category = "Contact Details";
        var keywords = $"contact, txt, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Contact TXT records publish administrative contact information.";
        var why = "Providing contact records helps external parties reach administrators.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || !analysis.RecordExists)
        {
            hi.Add("No contact TXT record found.");
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

        hi.Add("Contact TXT record found.");
        if (analysis.Fields.Count > 0)
        {
            hi.Add($"Fields parsed: {analysis.Fields.Count}.");
            det.AddRange(analysis.Fields.Select(kv => $"{kv.Key}: {kv.Value}"));
        }

        var refs = DefaultRefs();
        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out negatives, out remediations);
            }
        }
        catch (Exception)
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
        "https://www.rfc-editor.org/rfc/rfc2142"
    };
}
