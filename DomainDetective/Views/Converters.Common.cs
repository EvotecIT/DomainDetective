using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    internal static AnalysisArea AreaForKind(HealthCheckType check)
    {
        switch (check)
        {
            // DNS group
            case HealthCheckType.NS:
            case HealthCheckType.SOA:
            case HealthCheckType.EDNSSUPPORT:
            case HealthCheckType.REVERSEDNS:
            case HealthCheckType.FCRDNS:
            case HealthCheckType.DNSSEC:
            case HealthCheckType.CAA:
            case HealthCheckType.TTL:
            case HealthCheckType.WILDCARDDNS:
            case HealthCheckType.ZONETRANSFER:
            case HealthCheckType.DNSHEALTH:
            case HealthCheckType.APEXADDRESS:
                return AnalysisArea.DNS;

            // Mail group
            case HealthCheckType.MX:
            case HealthCheckType.SPF:
            case HealthCheckType.DKIM:
            case HealthCheckType.DMARC:
            case HealthCheckType.BIMI:
            case HealthCheckType.MTASTS:
            case HealthCheckType.TLSRPT:
            case HealthCheckType.STARTTLS:
            case HealthCheckType.SMTPTLS:
            case HealthCheckType.IMAPTLS:
            case HealthCheckType.POP3TLS:
            case HealthCheckType.SMTPAUTH:
            case HealthCheckType.SMTPBANNER:
            case HealthCheckType.MAILLATENCY:
            case HealthCheckType.SMIMEA:
            case HealthCheckType.AUTODISCOVER:
            case HealthCheckType.OPENRELAY:
            case HealthCheckType.SPFFLATTENED:
            case HealthCheckType.MAILCLASSIFICATION:
                return AnalysisArea.Mail;

            // Web group
            case HealthCheckType.HTTP:
            case HealthCheckType.CERT:
            case HealthCheckType.DANE:
            case HealthCheckType.SECURITYTXT:
            case HealthCheckType.DIRECTORYEXPOSURE:
            case HealthCheckType.WEBSITE:
                return AnalysisArea.Web;

            // Security/infra group
            case HealthCheckType.RDAP:
            case HealthCheckType.RPKI:
            case HealthCheckType.DNSBL:
            case HealthCheckType.WHOIS:
            case HealthCheckType.THREATINTEL:
            case HealthCheckType.THREATFEED:
            case HealthCheckType.IPNEIGHBOR:
            case HealthCheckType.PORTSCAN:
            case HealthCheckType.PORTAVAILABILITY:
            case HealthCheckType.DNSTUNNELING:
            case HealthCheckType.CONTACT:
                return AnalysisArea.Security;

            default:
                return AnalysisArea.General;
        }
    }

    // All converters now use enum-based mapping; string fallback removed.
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
