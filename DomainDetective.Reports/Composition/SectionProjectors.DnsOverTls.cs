using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    // DNS: DNS over TLS (DoT) support on authoritative name servers
    public sealed class DnsOverTlsSection
    {
        public sealed class EndpointRow
        {
            public string Key { get; set; } = string.Empty;
            public string NameServerHost { get; set; } = string.Empty;
            public string ServerIp { get; set; } = string.Empty;
            public int Port { get; set; }
            public bool Supported { get; set; }
            public string Protocol { get; set; } = "-";
            public string CipherSuite { get; set; } = "-";
            public string HostnameMatch { get; set; } = "-";
            public string CertificateValid { get; set; } = "-";
            public string Error { get; set; } = "-";
        }

        public string Status { get; set; } = "-";
        public int TotalChecked { get; set; }
        public int SupportedCount { get; set; }
        public int HostnameMismatchCount { get; set; }
        public int InvalidCertificateCount { get; set; }
        public int WarningCount { get; set; }
        public int ErrorCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<EndpointRow> Endpoints { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public static DnsOverTlsSection? BuildDnsOverTls(DomainDetective.Views.DnsOverTlsSummary summary)
    {
        if (summary == null)
        {
            return null;
        }

        var endpoints = summary.Endpoints ?? Array.Empty<DomainDetective.Views.DnsOverTlsEndpointInfo>();

        var sec = new DnsOverTlsSection
        {
            Status = summary.Status ?? "-",
            TotalChecked = summary.TotalChecked,
            SupportedCount = summary.SupportedCount,
            HostnameMismatchCount = summary.HostnameMismatchCount,
            InvalidCertificateCount = summary.InvalidCertificateCount,
            WarningCount = summary.WarningCount,
            ErrorCount = summary.ErrorCount
        };

        sec.Summary.Add(("Status", sec.Status));
        sec.Summary.Add(("Endpoints checked", sec.TotalChecked.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Supported", sec.SupportedCount.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Hostname mismatch", sec.HostnameMismatchCount.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Invalid certificate", sec.InvalidCertificateCount.ToString(CultureInfo.InvariantCulture)));

        static string Flag(bool? value)
        {
            if (!value.HasValue) return "-";
            return value.Value ? "Yes" : "No";
        }

        foreach (var e in endpoints.OrderByDescending(x => x.Supported).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
        {
            var nameServerHost = e.NameServerHost;
            var serverIp = e.ServerIp;
            var protocol = e.Protocol;
            var cipherSuite = e.CipherSuite;
            var error = e.Error;

            sec.Endpoints.Add(new DnsOverTlsSection.EndpointRow
            {
                Key = e.Key ?? string.Empty,
                NameServerHost = string.IsNullOrWhiteSpace(nameServerHost) ? "-" : nameServerHost,
                ServerIp = string.IsNullOrWhiteSpace(serverIp) ? "-" : serverIp,
                Port = e.Port,
                Supported = e.Supported,
                Protocol = string.IsNullOrWhiteSpace(protocol) ? "-" : (protocol ?? "-"),
                CipherSuite = string.IsNullOrWhiteSpace(cipherSuite) ? "-" : (cipherSuite ?? "-"),
                HostnameMatch = Flag(e.HostnameMatch),
                CertificateValid = Flag(e.CertificateValid),
                Error = string.IsNullOrWhiteSpace(error) ? "-" : (error ?? "-")
            });
        }

        foreach (var a in summary.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a == null || a.Severity == DomainDetective.AssessmentSeverity.Info)
            {
                continue;
            }
            sec.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }

        foreach (var p in summary.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var t = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(t))
            {
                sec.Positives.Add(t!);
            }
        }

        foreach (var r in summary.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(r))
            {
                sec.References.Add(r);
            }
        }

        return sec;
    }
}
