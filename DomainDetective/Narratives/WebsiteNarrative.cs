using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives
{
    public static class WebsiteNarrative
    {
        public sealed class Sections : NarrativeSections { }

        public static Sections Build(HttpAnalysis? http, TlsAnalysis? tls)
        {
            var subj = http?.Subject ?? tls?.Subject;
            subj = string.IsNullOrWhiteSpace(subj) ? "(host)" : subj!;
            var title = $"Website Security Report — {subj}";
            const string subtitle = "HTTPS and TLS Assessment";
            const string category = "Web Security";
            var keywords = $"website, https, tls, headers, DomainDetective, {subj}";
            const string creator = "DomainDetective";
            const string intro = "Combines HTTP headers and TLS handshake data to summarize website security.";
            const string why = "Strong TLS and defensive headers protect visitors from interception and injection.";

            var hi = new List<string>();
            var det = new List<string>();
            var positives = new List<string>();
            var remediations = new List<string>();

            if (http != null)
            {
                if (http.StatusCode.HasValue)
                {
                    hi.Add($"HTTP {http.StatusCode}.");
                }
                if (http.SecurityHeaders.Count > 0)
                {
                    hi.Add($"Security headers: {string.Join(", ", http.SecurityHeaders.Keys)}.");
                }
                if (http.MissingSecurityHeaders.Count > 0)
                {
                    det.Add($"Missing headers: {string.Join(", ", http.MissingSecurityHeaders)}");
                }
                foreach (var url in http.VisitedUrls)
                {
                    det.Add($"Visited {url}");
                }
            }
            else
            {
                hi.Add("No HTTP data available.");
            }

            if (tls != null)
            {
                foreach (var kv in tls.ServerResults)
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
            }
            else
            {
                hi.Add("No TLS data available.");
            }

            var allAssessments = new List<Assessment>();
            if (http?.Assessments != null) allAssessments.AddRange(http.Assessments);
            if (tls?.Assessments != null) allAssessments.AddRange(tls.Assessments);
            AssessmentSplit.SplitTitles(allAssessments, out positives, out remediations);

            var refs = new List<string>
            {
                "https://developer.mozilla.org/docs/Web/HTTP/Headers",
                "https://datatracker.ietf.org/doc/rfc8446/"
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
                Remediations = remediations.Distinct().ToList()
            };
        }
    }
}

