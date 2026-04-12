using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides smtp auth narrative functionality.</summary>
public static class SmtpAuthNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(SmtpAuthAnalysis? analysis)
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
        var title = $"SMTP AUTH Report — {subj}";
        var subtitle = "SMTP AUTH Assessment";
        var category = "Email Security";
        var keywords = $"SMTP AUTH, SASL, email, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SMTP AUTH allows clients to authenticate before sending mail.";
        var why = "Securing authentication prevents unauthorized use and protects credentials.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.ServerMechanisms.Count == 0)
        {
            hi.Add("No SMTP AUTH data available.");
        }
        else
        {
            foreach (var kv in analysis.ServerMechanisms)
            {
                var mechs = kv.Value.Length == 0 ? "(none)" : string.Join(" ", kv.Value);
                hi.Add($"{kv.Key} supports {mechs}");
                if (analysis.InspectCapabilities && analysis.ServerCapabilities.TryGetValue(kv.Key, out var caps))
                {
                    hi.Add(caps.Contains("STARTTLS", StringComparer.OrdinalIgnoreCase) ? $"{kv.Key} advertises STARTTLS." : $"{kv.Key} does not advertise STARTTLS.");
                }
            }
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>());
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc4954",
            "https://www.rfc-editor.org/rfc/rfc8314"
        };

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
