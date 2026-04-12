using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides tls narrative functionality.</summary>
public static class TlsNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(TlsAnalysis? analysis)
    {
        var subjCandidate = analysis?.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(host)";
        }
        var title = $"TLS Report — {subj}";
        var subtitle = "HTTPS TLS Assessment";
        var category = "Web Security";
        var keywords = $"TLS, HTTPS, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "TLS secures HTTPS connections and verifies server identity.";
        var why = "Modern protocols and ciphers protect confidentiality and integrity.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis != null)
        {
            foreach (var kv in analysis.ServerResults)
            {
                var r = kv.Value;
                var cipher = string.IsNullOrWhiteSpace(r.CipherSuite) ? r.KeyExchangeAlgorithm : r.CipherSuite;
                var certStatus = r.CertificateValid && r.ChainValid && r.HostnameMatch ? "valid certificate" : "certificate issues";
                hi.Add($"{kv.Key} negotiated {r.Protocol} ({cipher}) — {certStatus}.");
                if (!string.IsNullOrWhiteSpace(r.CertificateSubject) || !string.IsNullOrWhiteSpace(r.CertificateIssuer))
                {
                    det.Add($"{kv.Key} certificate: {r.CertificateSubject} issued by {r.CertificateIssuer}");
                }
            }
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>());
        }
        else
        {
            hi.Add("No TLS data available.");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/rfc8446/",
            "https://ssl-config.mozilla.org/"
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
            Positives = positives.Distinct().ToList(),
            Negatives = negatives,
            Remediations = remediations.Distinct().ToList()
        };
    }
}

