using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

/// <summary>Provides certificate http narrative functionality.</summary>
public static class CertificateHttpNarrative {
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(CertificateAnalysis? analysis, IEnumerable<Assessment>? assessments = null) {
        var intro = "Retrieves the TLS certificate over HTTPS and evaluates chain trust and expiry.";
        var why = "Trusted certificates with reasonable lifetimes prevent browser warnings and ensure secure connections.";

        if (analysis == null) {
            return new Sections {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No certificate data available." },
                Details = new List<string>(),
                References = DefaultRefs()
            };
        }

        var subj = string.IsNullOrWhiteSpace(analysis.Subject) ? "(domain)" : analysis.Subject;
        var title = $"HTTPS Certificate — {subj}";
        const string subtitle = "TLS Certificate Assessment";
        const string category = "Web Security";
        var keywords = $"TLS, certificate, DomainDetective, {subj}";
        const string creator = "DomainDetective";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

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
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
            }
        } catch (Exception ex) {
            System.Diagnostics.Debug.WriteLine(ex);
        }

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

    private static List<string> DefaultRefs() => new() {
        "https://datatracker.ietf.org/doc/html/rfc5280",
        "https://letsencrypt.org/docs/"
    };
}
