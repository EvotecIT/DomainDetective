using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives
{
    public static class SoaNarrative
    {
        public sealed class Sections : NarrativeSections { }

        public static Sections Build(SOAAnalysis soa)
        {
            var subj = string.IsNullOrWhiteSpace(soa.Subject) ? "(domain)" : soa.Subject;
            var title = $"SOA Report — {subj}";
            var subtitle = "Start of Authority Assessment";
            var category = "DNS Infrastructure";
            var keywords = $"SOA, DNS, DomainDetective, {subj}";
            var creator = "DomainDetective";
            var intro = "The Start of Authority (SOA) record defines zone parameters such as the primary nameserver and timing values.";
            var why = "Sensible SOA settings ensure reliable zone transfers and predictable caching behaviour.";

            var hi = new List<string>();
            var det = new List<string>();
            var positives = new List<string>();
        var negatives = new List<string>();
            var remediations = new List<string>();

            if (soa.RecordExists)
            {
                if (!string.IsNullOrWhiteSpace(soa.PrimaryNameServer))
                {
                    hi.Add($"Primary NS: {soa.PrimaryNameServer}");
                }
                hi.Add($"Serial: {soa.SerialNumber}");
                hi.Add($"Refresh: {soa.Refresh}s");
                hi.Add($"Retry: {soa.Retry}s");
                hi.Add($"Expire: {soa.Expire}s");

                if (!string.IsNullOrWhiteSpace(soa.ResponsibleMailbox))
                {
                    det.Add($"RNAME: {soa.ResponsibleMailbox}");
                }
                det.Add($"Serial: {soa.SerialNumber}");
                det.Add($"Refresh: {soa.Refresh}s");
                det.Add($"Retry: {soa.Retry}s");
                det.Add($"Expire: {soa.Expire}s");
                det.Add($"Minimum TTL: {soa.Minimum}s");
            }
            else
            {
                hi.Add("No SOA record is published.");
            }
            if (!string.IsNullOrWhiteSpace(soa.Subject))
            {
                det.Add($"Subject: {soa.Subject}");
            }

            var refs = new List<string>
            {
                "https://www.rfc-editor.org/rfc/rfc1035"
            };

            try
            {
                var assessments = (IEnumerable<Assessment>)(soa.Assessments ?? new List<Assessment>());
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
                Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            };
        }
    }
}
