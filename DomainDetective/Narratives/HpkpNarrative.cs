using System.Collections.Generic;

namespace DomainDetective.Narratives {
    public static class HpkpNarrative {
        public sealed class Sections : NarrativeSections { }

        public static Sections Build(HPKPAnalysis analysis) {
            var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(host)" : analysis.Subject!;
            var title = $"HPKP Report — {subj}";
            var subtitle = "HPKP Assessment";
            var category = "Web Security";
            var keywords = $"HPKP, security, DomainDetective, {subj}";
            var creator = "DomainDetective";
            var intro = "HTTP Public Key Pinning (HPKP) once bound browsers to specific certificate public keys.";
            var why = "HPKP is deprecated and misconfiguration can lock users out.";

            var hi = new List<string>();
            var det = new List<string>();
            var positives = new List<string>();
            var negatives = new List<string>();
            var remediations = new List<string>();

            if (analysis != null) {
                if (analysis.HeaderPresent) {
                    hi.Add("Public-Key-Pins header present.");
                    hi.Add(analysis.PinsValid ? "Pins are valid." : "Pins are invalid.");
                    if (analysis.IncludesSubDomains) {
                        hi.Add("includeSubDomains directive present.");
                    }
                    hi.Add("HPKP is deprecated; consider removing the header.");
                    det.Add($"max-age: {analysis.MaxAge}");
                    if (analysis.Pins.Count > 0) {
                        det.Add($"pins: {string.Join(", ", analysis.Pins)}");
                    }
                } else {
                    hi.Add("No Public-Key-Pins header found.");
                }
                AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);
            } else {
                hi.Add("No HPKP data available.");
            }

            var refs = new List<string> {
                "https://datatracker.ietf.org/doc/html/rfc7469",
                "https://developer.chrome.com/blog/chrome-security-headers/#public-key-pinning-hpkp"
            };

            return new Sections {
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
