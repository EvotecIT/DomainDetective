using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class MailClassificationNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(MailDomainClassificationResult result)
    {
        var subj = string.IsNullOrWhiteSpace(result?.Domain) ? "(domain)" : result.Domain;
        var title = $"Mail Classification — {subj}";
        var subtitle = "Mail Posture";
        var category = "Email Security";
        var keywords = $"mail, classification, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Determines whether a domain sends or receives email.";
        var why = "Understanding mail posture helps manage risk and expectations.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        hi.Add($"Classification: {result.Classification}");
        hi.Add($"Confidence: {result.Confidence}");

        if (result.ReceivingSignals?.Count > 0)
            det.Add($"Receiving signals: {string.Join(", ", result.ReceivingSignals)}");
        if (result.SendingSignals?.Count > 0)
            det.Add($"Sending signals: {string.Join(", ", result.SendingSignals)}");
        if (!string.IsNullOrWhiteSpace(result.ClassificationReason))
            det.Add(result.ClassificationReason);

        var refs = result.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList()
            ?? new List<string>();

        try
        {
            var assessments = (IEnumerable<Assessment>)(result.Assessments ?? new List<Assessment>());
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
