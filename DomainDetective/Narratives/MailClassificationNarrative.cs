using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides mail classification narrative functionality.</summary>
public static class MailClassificationNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(MailDomainClassificationResult result)
    {
        var subj = string.IsNullOrWhiteSpace(result.Domain) ? "(domain)" : result.Domain;
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
