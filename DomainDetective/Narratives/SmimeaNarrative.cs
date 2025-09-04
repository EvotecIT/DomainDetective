using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class SmimeaNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(SMIMEAAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(email)" : analysis.Subject;
        var title = $"SMIMEA Report — {subj}";
        var subtitle = "SMIMEA Assessment";
        var category = "Email Security";
        var keywords = $"SMIMEA, email, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SMIMEA publishes S/MIME certificate associations in DNS, secured by DNSSEC.";
        var why = "Publishing SMIMEA allows recipients to validate S/MIME certificates before trusting messages.";

        var highlights = new List<string>();
        var details = new List<string>();

        if (analysis == null || analysis.NumberOfRecords == 0)
        {
            highlights.Add("No SMIMEA records found.");
        }
        else
        {
            highlights.Add($"{analysis.NumberOfRecords} SMIMEA record(s) found.");
            if (analysis.HasDuplicateRecords) highlights.Add("Duplicate SMIMEA records detected.");
            if (analysis.HasInvalidRecords) highlights.Add("One or more SMIMEA records are invalid.");
            else highlights.Add("All SMIMEA records are valid.");
        }

        if (analysis?.AnalysisResults != null)
        {
            foreach (var r in analysis.AnalysisResults)
            {
                details.Add($"{r.EmailAddress ?? string.Empty} — {r.CertificateUsage}, {r.SelectorField}, {r.MatchingTypeField}");
            }
        }

        var refs = new List<string> { "https://www.rfc-editor.org/rfc/rfc8162" };

        List<string> positives;
        List<string> remediations;
        try
        {
            AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>(), out positives, out remediations);
        }
        catch (Exception)
        {
            positives = new List<string>();
            remediations = new List<string>();
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
            Highlights = highlights,
            Details = details,
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }
}

