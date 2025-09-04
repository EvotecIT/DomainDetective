using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives {
    public static class SecurityTxtNarrative {
        public sealed class Sections {
            public string Title { get; init; } = string.Empty;
            public string Subtitle { get; init; } = string.Empty;
            public string Category { get; init; } = string.Empty;
            public string Keywords { get; init; } = string.Empty;
            public string Creator { get; init; } = string.Empty;
            public string Introduction { get; init; } = string.Empty;
            public string WhyItMatters { get; init; } = string.Empty;
            public List<string> Highlights { get; init; } = new();
            public List<string> Details { get; init; } = new();
            public List<string> References { get; init; } = new();
            public List<string> Positives { get; init; } = new();
            public List<string> Remediations { get; init; } = new();
        }

        public static Sections Build(SecurityTXTAnalysis analysis) {
            var subj = string.IsNullOrWhiteSpace(analysis?.Domain) ? "(domain)" : analysis.Domain;
            var title = $"security.txt Report — {subj}";
            var subtitle = "Security Policy";
            var category = "Vulnerability Disclosure";
            var keywords = $"security.txt, vulnerability disclosure, DomainDetective, {subj}";
            var creator = "DomainDetective";
            var intro = "security.txt provides a standard location for vulnerability disclosure policies and contacts.";
            var why = "Publishing security.txt helps researchers report vulnerabilities responsibly and securely.";

            var hi = new List<string>();
            var det = new List<string>();
            var positives = new List<string>();
            var remediations = new List<string>();

            var contacts = analysis.ContactEmail.Concat(analysis.ContactWebsite).ToList();
            hi.Add(contacts.Count > 0
                ? $"Contacts: {string.Join(", ", contacts)}"
                : "No contact methods provided.");

            if (analysis.Encryption.Count > 0) {
                hi.Add($"Encryption keys: {string.Join(", ", analysis.Encryption)}");
            }

            if (analysis.Policy.Count > 0) {
                hi.Add($"Policies: {string.Join(", ", analysis.Policy)}");
            }

            if (analysis.PGPSigned) {
                det.Add("PGP signed file.");
            }

            if (analysis.Canonical.Count > 0) {
                det.Add($"Canonical: {string.Join(", ", analysis.Canonical)}");
            }

            if (!string.IsNullOrWhiteSpace(analysis.Expires)) {
                det.Add($"Expires: {analysis.Expires}");
            }

            var refs = new List<string> { "https://securitytxt.org/" };

            try {
                AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out remediations);
            } catch { }

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
                Remediations = remediations
            };
        }
    }
}

