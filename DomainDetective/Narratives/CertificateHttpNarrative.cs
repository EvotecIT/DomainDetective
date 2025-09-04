using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class CertificateHttpNarrative {
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

    public static Sections Build(CertificateAnalysis analysis, IEnumerable<Assessment>? assessments = null) {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"HTTPS Certificate — {subj}";
        var subtitle = "TLS Certificate Assessment";
        var category = "Web Security";
        var keywords = $"TLS, certificate, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Retrieves the TLS certificate over HTTPS and evaluates chain trust and expiry.";
        var why = "Trusted certificates with reasonable lifetimes prevent browser warnings and ensure secure connections.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null) {
            return new Sections {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No certificate data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.IsReachable
            ? $"Successfully retrieved certificate from {analysis.Url ?? subj}."
            : $"Failed to retrieve certificate from {analysis.Url ?? subj}.");
        hi.Add(analysis.IsValid ? "Certificate chain is valid." : "Certificate chain is invalid.");
        hi.Add(analysis.IsExpired ? "Certificate has expired." : $"Certificate expires in {analysis.DaysToExpire} days.");

        if (analysis.Certificate != null) {
            det.Add($"Subject: {analysis.Certificate.Subject}");
            det.Add($"Issuer: {analysis.Certificate.Issuer}");
            det.Add($"NotAfter: {analysis.Certificate.NotAfter:u}");
        }

        var refs = DefaultRefs();

        try {
            if (assessments != null) {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
            }
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

    private static List<string> DefaultRefs() => new() {
        "https://datatracker.ietf.org/doc/html/rfc5280",
        "https://letsencrypt.org/docs/"
    };
}
