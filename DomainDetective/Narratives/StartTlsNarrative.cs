using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class StartTlsNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(STARTTLSAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"STARTTLS Report — {subj}";
        var subtitle = "STARTTLS Assessment";
        var category = "Email Security";
        var keywords = $"STARTTLS, SMTP, IMAP, POP, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "STARTTLS upgrades plaintext mail protocols like SMTP, IMAP and POP to encrypted TLS sessions.";
        var why = "Enforcing STARTTLS with modern ciphers prevents downgrade attacks and eavesdropping.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis != null && analysis.ServerDetails.Count > 0)
        {
            foreach (var kv in analysis.ServerDetails)
            {
                var r = kv.Value;
                var proto = r.Port switch
                {
                    25 or 587 or 465 => "SMTP",
                    143 or 993 => "IMAP",
                    110 or 995 => "POP3",
                    _ => "Server"
                };
                var status = r.StartTlsAdvertised ? "advertises STARTTLS" : "does not advertise STARTTLS";
                var upgrade = r.TlsNegotiated ? $"upgraded to {r.TlsProtocol} ({r.CipherAlgorithm} {r.CipherStrength} bits)" : "no TLS negotiation";
                var downgrade = r.DowngradeDetected ? " (downgrade suspected)" : string.Empty;
                hi.Add($"{kv.Key} [{proto}] {status} and {upgrade}{downgrade}.");
                det.Add($"{kv.Key} downgrade detected: {r.DowngradeDetected}");
            }
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>());
        }
        else
        {
            hi.Add("No STARTTLS data available.");
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc3207",
            "https://www.rfc-editor.org/rfc/rfc2595",
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

