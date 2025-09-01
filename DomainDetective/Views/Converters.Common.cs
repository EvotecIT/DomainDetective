using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    internal static string AreaFor(string check)
    {
        var c = (check ?? string.Empty).ToUpperInvariant();
        if (c is "NS" or "SOA" or "EDNS" or "RDNS" or "FCRDNS" or "DNSSEC" or "CAA" or "TTL" or "WILDCARD" or "AXFR" or "APEX") return "DNS";
        if (c is "MX" or "SPF" or "DKIM" or "DMARC" or "BIMI" or "MTASTS" or "TLSRPT" or "STARTTLS" or "SMTP" or "IMAPTLS" or "POP3TLS" or "SMTPAUTH" or "SMTPBANNER" or "LATENCY" or "SMIMEA" or "AUTODISCOVER" or "OPENRELAY") return "Mail";
        if (c is "HTTP" or "CERT" or "DANE" or "SECURITYTXT" or "DIRECTORY") return "Web";
        if (c is "RDAP" or "RPKI" or "DNSBL" or "THREAT" or "THREATFEED" or "IPNEIGHBOR" or "PORTSCAN" or "PORTAVAILABILITY" or "DNSTUNNELING" or "CONTACT") return "Security";
        return "General";
    }
    internal static IReadOnlyList<string> BuildReferences(IReadOnlyList<StandardReference> refs, IEnumerable<RecommendationAdvice> advices)
    {
        var list = new List<string>();
        if (refs != null)
        {
            foreach (var r in refs)
            {
                if (!string.IsNullOrWhiteSpace(r?.Url)) list.Add(r.Url);
                else if (!string.IsNullOrWhiteSpace(r?.Reference)) list.Add(r.Reference);
            }
        }
        if (advices != null)
        {
            foreach (var a in advices)
            {
                if (a?.Links != null)
                    foreach (var l in a.Links)
                        if (!string.IsNullOrWhiteSpace(l)) list.Add(l);
            }
        }
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    internal static void Summarize(IReadOnlyList<Assessment> assessments, out int warningCount, out int errorCount, out string status)
    {
        warningCount = 0;
        errorCount = 0;
        if (assessments != null)
        {
            foreach (var a in assessments)
            {
                if (a == null) continue;
                if (a.Severity == AssessmentSeverity.Error) errorCount++;
                else if (a.Severity == AssessmentSeverity.Warning) warningCount++;
            }
        }
        status = errorCount > 0 ? "Error" : (warningCount > 0 ? "Warning" : "OK");
    }
}
