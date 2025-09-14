using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives
{
    public static class MailTlsNarrative
    {
        public sealed class Sections : NarrativeSections { }

    public static Sections Build(MailTlsAnalysis analysis, MailTlsAnalysis.MailProtocol protocol)
        {
            var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
            var protoName = protocol switch
            {
                MailTlsAnalysis.MailProtocol.Smtp => "SMTP",
                MailTlsAnalysis.MailProtocol.Imap => "IMAP",
                MailTlsAnalysis.MailProtocol.Pop3 => "POP3",
                _ => "MAIL"
            };
            var title = $"{protoName} TLS Report — {subj}";
            var subtitle = $"{protoName} TLS Assessment";
            var category = "Email Security";
            var keywords = $"TLS, {protoName}, email, security, DomainDetective, {subj}";
            var creator = "DomainDetective";
            var intro = "Transport Layer Security (TLS) encrypts mail transport and verifies server identity.";
            var why = "Strong TLS reduces interception risk and improves deliverability and trust.";

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
                    var cipher = string.IsNullOrWhiteSpace(r.CipherSuite) ? $"{r.CipherAlgorithm} {r.CipherStrength} bits" : r.CipherSuite;
                    var certStatus = r.CertificateValid && r.ChainValid && !r.IsExpired && r.HostnameMatch ? "valid certificate" : "certificate issues";
                    hi.Add($"{kv.Key} negotiated {r.Protocol} ({cipher}) — {certStatus}.");
                    det.Add($"{kv.Key} expires in {r.DaysToExpire} days");
                }
                AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);
            }
            else
            {
                hi.Add("No TLS data available.");
            }

            var refs = new List<string>
            {
                "https://datatracker.ietf.org/doc/html/rfc7817",
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
            Negatives = negatives.Distinct().ToList(),
            Remediations = remediations.Distinct().ToList()
            };
        }
    }
}
