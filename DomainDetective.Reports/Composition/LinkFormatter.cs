using System;
using System.Text.RegularExpressions;

namespace DomainDetective.Reports;

public static class LinkFormatter
{
    private static readonly Regex RfcNumInUrl = new Regex(@"rfc(?<num>\d{3,5})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RfcNumInText = new Regex(@"RFC\s*-?\s*(?<num>\d{3,5})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Minimal curated map of RFC number -> (topic tag, short description)
    // Extend as needed when new sections reference additional RFCs.
    private static readonly System.Collections.Generic.Dictionary<string, (string Topic, string Desc)> RfcMeta
        = new System.Collections.Generic.Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase) {
            // Email auth
            { "7208", ("SPF",   "Sender Policy Framework") },
            { "6376", ("DKIM",  "DomainKeys Identified Mail") },
            { "8301", ("DKIM",  "Cryptographic Advice for DKIM") },
            { "7489", ("DMARC", "Domain-based Message Authentication, Reporting, and Conformance") },
            // Transport & reports
            { "8461", ("MTA-STS", "SMTP Strict Transport Security") },
            { "8460", ("TLS-RPT", "SMTP TLS Reporting") },
            // SMTP / message format
            { "5321", ("SMTP",  "Simple Mail Transfer Protocol") },
            { "5322", ("Email", "Internet Message Format") },
            // DNS & DNSSEC
            { "1034", ("DNS",   "Domain Names — Concepts and Facilities") },
            { "1035", ("DNS",   "Domain Names — Implementation and Specification") },
            { "1912", ("DNS",   "Common DNS Operational and Configuration Errors") },
            { "2181", ("DNS",   "Clarifications to the DNS Specification") },
            { "2182", ("DNS",   "Selection and Operation of Secondary DNS Servers") },
            { "4035", ("DNSSEC","Protocol Modifications") },
            // DANE / TLSA
            { "6698", ("DANE",  "DANE TLSA Authentication") },
            { "7671", ("DANE",  "DANE Operations") },
            { "7672", ("SMTP",  "SMTP Security via Opportunistic DANE TLSA") },
            // Address ranges
            { "6890", ("IP",    "Special-Purpose Address Registries") },
            // security.txt
            { "9116", ("Security.txt", "A File Format to Aid in Security Vulnerability Disclosure") },
        };

    public static (string Title, string Url) Format(string reference)
    {
        if (string.IsNullOrWhiteSpace(reference)) return (string.Empty, string.Empty);
        string url = reference.Trim();
        string title = reference.Trim();

        if (Uri.TryCreate(reference, UriKind.Absolute, out var uri))
        {
            // RFC patterns across rfc-editor.org or datatracker paths
            var m = RfcNumInUrl.Match(uri.AbsolutePath);
            if (m.Success)
            {
                var num = m.Groups["num"].Value;
                title = BuildRfcTitle(num);
                // Prefer rfc-editor canonical URL
                url = $"https://www.rfc-editor.org/rfc/rfc{num}";
                return (title, url);
            }

            // Fallback: humanize from host + last segment
            var host = uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? uri.Host.Substring(4) : uri.Host;
            string seg = string.Empty;
            if (uri.Segments != null && uri.Segments.Length > 0)
            {
                seg = uri.Segments[uri.Segments.Length - 1].Trim('/');
            }
            seg = seg.Replace('-', ' ').Replace('_', ' ');
            if (string.IsNullOrWhiteSpace(seg)) seg = host;
            title = $"{host} — {seg}";
            return (title, uri.ToString());
        }
        else
        {
            // Text like "RFC 1912" → map to canonical URL with title
            var t = reference.Trim();
            var m = RfcNumInText.Match(t);
            if (m.Success)
            {
                var num = m.Groups["num"].Value;
                return (BuildRfcTitle(num), $"https://www.rfc-editor.org/rfc/rfc{num}");
            }
            return (t, t);
        }
    }

    private static string BuildRfcTitle(string num)
    {
        if (string.IsNullOrWhiteSpace(num)) return "RFC";
        if (RfcMeta.TryGetValue(num, out var meta))
        {
            // Example: "RFC 7208 — SPF: Sender Policy Framework"
            var topic = meta.Topic;
            var desc = meta.Desc;
            if (!string.IsNullOrWhiteSpace(topic) && !string.IsNullOrWhiteSpace(desc))
                return $"RFC {num} — {topic}: {desc}";
            if (!string.IsNullOrWhiteSpace(desc)) return $"RFC {num} — {desc}";
            if (!string.IsNullOrWhiteSpace(topic)) return $"RFC {num} — {topic}";
        }
        return $"RFC {num}";
    }
}
