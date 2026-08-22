using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static StartTlsInfo Convert(STARTTLSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var entries = analysis.ServerDetails?.Select(kv => new StartTlsServerInfo
        {
            Key = kv.Key,
            HostName = kv.Value.Connection.HostName,
            Port = kv.Value.Connection.Port,
            ConnectAddress = kv.Value.Connection.ConnectAddress,
            RequestedAddressFamily = kv.Value.Connection.RequestedAddressFamily,
            RemoteAddress = kv.Value.Connection.RemoteAddress,
            RemoteAddressFamily = kv.Value.Connection.RemoteAddressFamily,
            StartTlsAdvertised = kv.Value.StartTlsAdvertised,
            TlsNegotiated = kv.Value.TlsNegotiated,
            DowngradeDetected = kv.Value.DowngradeDetected,
            TlsProtocol = kv.Value.TlsProtocol,
            CipherAlgorithm = kv.Value.CipherAlgorithm,
            CipherStrength = kv.Value.CipherStrength,
            CertificateSubject = kv.Value.CertificateSubject,
            CertificateIssuer = kv.Value.CertificateIssuer,
            CertificateNotAfter = kv.Value.CertificateNotAfter
        }).ToList() ?? new List<StartTlsServerInfo>();
        return new StartTlsInfo
        {
            Check = HealthCheckType.STARTTLS,
            Area = AreaForKind(HealthCheckType.STARTTLS),
            Subject = analysis.Subject,
            Servers = entries,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"servers {entries.Count}; negotiated {entries.Count(s => s.TlsNegotiated)}/{entries.Count}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc3207" },
            Raw = analysis
        };
    }
}

/// <summary>Provides start tls info functionality.</summary>
public class StartTlsInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyList<StartTlsServerInfo> Servers { get; set; } = null!;
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
    public STARTTLSAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides start tls server info functionality.</summary>
public class StartTlsServerInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Logical hostname used for protocol identity and TLS validation.</summary>
    public string HostName { get; set; } = string.Empty;
    /// <summary>TCP port used by the probe.</summary>
    public int Port { get; set; }
    /// <summary>Concrete address requested by the caller, when pinned.</summary>
    public string? ConnectAddress { get; set; }
    /// <summary>Address family requested by the caller.</summary>
    public MailTransportAddressFamily RequestedAddressFamily { get; set; }
    /// <summary>Remote address observed after connecting.</summary>
    public string? RemoteAddress { get; set; }
    /// <summary>Address family observed after connecting.</summary>
    public MailTransportAddressFamily? RemoteAddressFamily { get; set; }
    /// <summary>Gets or sets the start tls advertised value.</summary>
    public bool StartTlsAdvertised { get; set; }
    /// <summary>Gets or sets the tls negotiated value.</summary>
    public bool TlsNegotiated { get; set; }
    /// <summary>Gets or sets the downgrade detected value.</summary>
    public bool DowngradeDetected { get; set; }
    /// <summary>Gets or sets the tls protocol value.</summary>
    public string? TlsProtocol { get; set; }
    /// <summary>Gets or sets the cipher algorithm value.</summary>
    public string? CipherAlgorithm { get; set; }
    /// <summary>Gets or sets the cipher strength value.</summary>
    public int? CipherStrength { get; set; }
    /// <summary>Gets or sets the certificate subject value.</summary>
    public string? CertificateSubject { get; set; }
    /// <summary>Gets or sets the certificate issuer value.</summary>
    public string? CertificateIssuer { get; set; }
    /// <summary>Gets or sets the certificate not after value.</summary>
    public System.DateTime? CertificateNotAfter { get; set; }
}
