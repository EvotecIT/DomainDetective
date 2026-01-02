using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters {
    public static DnsOverTlsSummary Convert(DnsOverTlsAnalysis analysis) {
        var total = analysis.ServerResults?.Count ?? 0;
        var endpoints = analysis.ServerResults?.Select(kv => new DnsOverTlsEndpointInfo {
            Key = kv.Key,
            NameServerHost = kv.Value.NameServerHost,
            ServerIp = kv.Value.ServerIp,
            Port = kv.Value.Port,
            Supported = kv.Value.Supported,
            Protocol = kv.Value.Protocol,
            CipherSuite = kv.Value.CipherSuite,
            HostnameMatch = kv.Value.HostnameMatch,
            CertificateValid = kv.Value.CertificateValid,
            Error = kv.Value.Error,
        }).ToList() ?? new List<DnsOverTlsEndpointInfo>();

        var supported = endpoints.Count(e => e.Supported);
        var mismatch = endpoints.Count(e => e.Supported && e.HostnameMatch == false);
        var invalidCert = endpoints.Count(e => e.Supported && e.CertificateValid == false);

        var assessments = analysis.Assessments ?? new List<Assessment>();
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        Summarize(assessments, out var warnCount, out var errCount, out var status);

        return new DnsOverTlsSummary {
            Check = HealthCheckType.DNSOVERTLS,
            Area = AreaForKind(HealthCheckType.DNSOVERTLS),
            Subject = analysis.Subject,
            TotalChecked = total,
            SupportedCount = supported,
            HostnameMismatchCount = mismatch,
            InvalidCertificateCount = invalidCert,
            Endpoints = endpoints,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = string.Format(CultureInfo.InvariantCulture, "endpoints {0}; supported {1}; mismatch {2}; invalid-cert {3}", total, supported, mismatch, invalidCert),
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public sealed class DnsOverTlsSummary {
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int TotalChecked { get; set; }
    public int SupportedCount { get; set; }
    public int HostnameMismatchCount { get; set; }
    public int InvalidCertificateCount { get; set; }
    public IReadOnlyList<DnsOverTlsEndpointInfo> Endpoints { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsOverTlsAnalysis Raw { get; set; } = null!;
}

public sealed class DnsOverTlsEndpointInfo {
    public string Key { get; set; } = null!;
    public string NameServerHost { get; set; } = string.Empty;
    public string ServerIp { get; set; } = string.Empty;
    public int Port { get; set; }
    public bool Supported { get; set; }
    public string? Protocol { get; set; }
    public string? CipherSuite { get; set; }
    public bool? HostnameMatch { get; set; }
    public bool? CertificateValid { get; set; }
    public string? Error { get; set; }
}

