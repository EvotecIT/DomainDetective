using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class BimiNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(BimiAnalysis bimi)
    {
        var subj = bimi?.Subject;
        if (string.IsNullOrWhiteSpace(subj))
        {
            subj = "(domain)";
        }
        var title = $"BIMI Report — {subj}";
        var subtitle = "BIMI Assessment";
        var category = "Email Branding";
        var keywords = $"BIMI, email, branding, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Brand Indicators for Message Identification (BIMI) lets a domain publish a logo that supporting mail clients can display.";
        var why = "A valid BIMI record with a compliant SVG and a verified certificate builds trust and strengthens brand recognition.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        hi.Add(bimi.BimiRecordExists
            ? "BIMI record is published and begins with v=BIMI1."
            : "No BIMI record is published.");

        if (bimi.SvgFetched)
        {
            hi.Add(bimi.SvgValid
                ? "BIMI SVG passed validation checks."
                : $"BIMI SVG failed validation: {bimi.SvgInvalidReason ?? "unknown reason"}.");
        }

        if (bimi.ValidVmc)
        {
            hi.Add(bimi.VmcSignedByKnownRoot
                ? "BIMI certificate is valid and trusted."
                : "BIMI certificate present but not issued by a trusted authority.");
        }

        if (!string.IsNullOrWhiteSpace(bimi.Location))
        {
            det.Add($"Indicator location: {bimi.Location}");
        }

        if (!string.IsNullOrWhiteSpace(bimi.Authority))
        {
            det.Add($"Certificate location: {bimi.Authority}");
        }

        if (!string.IsNullOrWhiteSpace(bimi.FailureReason))
        {
            det.Add($"Failure reason: {bimi.FailureReason}");
        }

        var refs = bimi.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList()
                   ?? new List<string> { "https://bimigroup.org/" };

        try
        {
            var assessments = (IEnumerable<Assessment>)(bimi.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                var msg = string.IsNullOrWhiteSpace(g.Advice?.Title)
                    ? (g.Instances.FirstOrDefault()?.Message ?? g.Code)
                    : g.Advice.Title;
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
        catch (Exception ex)
        {
            // Continue building narrative even if assessment grouping fails.
            Console.Error.WriteLine($"[BIMI narrative] assessment processing error: {ex.Message}");
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
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
