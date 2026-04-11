using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides dns over tls summary functionality.</summary>
public sealed class DnsOverTlsSummary {
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the supported count value.</summary>
    public int SupportedCount { get; set; }
    /// <summary>Gets or sets the hostname mismatch count value.</summary>
    public int HostnameMismatchCount { get; set; }
    /// <summary>Gets or sets the invalid certificate count value.</summary>
    public int InvalidCertificateCount { get; set; }
    /// <summary>Gets or sets the endpoints value.</summary>
    public IReadOnlyList<DnsOverTlsEndpointInfo> Endpoints { get; set; } = null!;
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public DnsOverTlsAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides dns over tls endpoint info functionality.</summary>
public sealed class DnsOverTlsEndpointInfo {
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Gets or sets the name server host value.</summary>
    public string NameServerHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the server ip value.</summary>
    public string ServerIp { get; set; } = string.Empty;
    /// <summary>Gets or sets the port value.</summary>
    public int Port { get; set; }
    /// <summary>Gets or sets the supported value.</summary>
    public bool Supported { get; set; }
    /// <summary>Gets or sets the protocol value.</summary>
    public string? Protocol { get; set; }
    /// <summary>Gets or sets the cipher suite value.</summary>
    public string? CipherSuite { get; set; }
    /// <summary>Gets or sets the hostname match value.</summary>
    public bool? HostnameMatch { get; set; }
    /// <summary>Gets or sets the certificate valid value.</summary>
    public bool? CertificateValid { get; set; }
    /// <summary>Gets or sets the error value.</summary>
    public string? Error { get; set; }
}

