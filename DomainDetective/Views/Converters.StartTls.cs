using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static StartTlsInfo Convert(STARTTLSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var entries = analysis.ServerDetails?.Select(kv => new StartTlsServerInfo
        {
            Key = kv.Key,
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
            Check = "STARTTLS",
            Subject = null,
            Servers = entries,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc3207" },
            Raw = analysis
        };
    }
}

public class StartTlsInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<StartTlsServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public STARTTLSAnalysis Raw { get; set; }
}

public class StartTlsServerInfo
{
    public string Key { get; set; }
    public bool StartTlsAdvertised { get; set; }
    public bool TlsNegotiated { get; set; }
    public bool DowngradeDetected { get; set; }
    public string TlsProtocol { get; set; }
    public string CipherAlgorithm { get; set; }
    public int? CipherStrength { get; set; }
    public string CertificateSubject { get; set; }
    public string CertificateIssuer { get; set; }
    public System.DateTime? CertificateNotAfter { get; set; }
}

