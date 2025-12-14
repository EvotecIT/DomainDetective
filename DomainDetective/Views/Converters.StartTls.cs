using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static StartTlsInfo Convert(STARTTLSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
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

public class StartTlsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public IReadOnlyList<StartTlsServerInfo> Servers { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public STARTTLSAnalysis Raw { get; set; } = null!;
}

public class StartTlsServerInfo
{
    public string Key { get; set; } = null!;
    public bool StartTlsAdvertised { get; set; }
    public bool TlsNegotiated { get; set; }
    public bool DowngradeDetected { get; set; }
    public string? TlsProtocol { get; set; }
    public string? CipherAlgorithm { get; set; }
    public int? CipherStrength { get; set; }
    public string? CertificateSubject { get; set; }
    public string? CertificateIssuer { get; set; }
    public System.DateTime? CertificateNotAfter { get; set; }
}
