using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MailTlsInfo Convert(SMTPTLSAnalysis analysis) => ConvertCore(analysis, "SMTPTLS");
    public static MailTlsInfo Convert(IMAPTLSAnalysis analysis) => ConvertCore(analysis, "IMAPTLS");
    public static MailTlsInfo Convert(POP3TLSAnalysis analysis) => ConvertCore(analysis, "POP3TLS");

    private static MailTlsInfo ConvertCore(MailTlsAnalysis analysis, string check)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var servers = new List<MailTlsServerInfo>();
        foreach (var kv in analysis.ServerResults)
        {
            var r = kv.Value;
            servers.Add(new MailTlsServerInfo
            {
                Key = kv.Key,
                StartTlsAdvertised = r.StartTlsAdvertised,
                Grade = r.GradeLevel,
                CertificateValid = r.CertificateValid,
                ChainValid = r.ChainValid,
                DaysToExpire = r.DaysToExpire,
                IsExpired = r.IsExpired,
                Protocol = r.Protocol.ToString(),
                SupportsTls13 = r.SupportsTls13,
                Tls13Used = r.Tls13Used,
                HostnameMatch = r.HostnameMatch,
                CipherAlgorithm = r.CipherAlgorithm.ToString(),
                CipherStrength = r.CipherStrength,
                CipherSuite = r.CipherSuite,
                KeyExchangeAlgorithm = r.KeyExchangeAlgorithm ?? string.Empty,
                DhKeyBits = r.DhKeyBits,
                CertificateSubject = r.CertificateSubject ?? string.Empty,
                CertificateIssuer = r.CertificateIssuer ?? string.Empty,
                CertificateNotAfter = r.CertificateNotAfter,
                // New summary-friendly aliases
                Issuer = r.CertificateIssuer,
                ValidFrom = r.CertificateNotBefore,
                ValidTo = r.CertificateNotAfter,
                Thumbprint = r.CertificateThumbprint
            });
        }
        int validCount = 0;
        var gradeCounts = new Dictionary<GradeLevel,int>();
        foreach (var s in servers)
        {
            if (s.CertificateValid) validCount++;
            if (s.Grade != GradeLevel.Unknown)
                gradeCounts[s.Grade] = (gradeCounts.TryGetValue(s.Grade, out var c) ? c : 0) + 1;
        }
        string gradesSummary = gradeCounts.Count > 0
            ? string.Join("/", new[]{GradeLevel.A,GradeLevel.B,GradeLevel.C,GradeLevel.D,GradeLevel.F}.Select(g => gradeCounts.TryGetValue(g, out var c) ? c.ToString() : "0"))
            : string.Empty;
        var kind = check switch { "SMTPTLS" => HealthCheckType.SMTPTLS, "IMAPTLS" => HealthCheckType.IMAPTLS, "POP3TLS" => HealthCheckType.POP3TLS, _ => HealthCheckType.STARTTLS };
        return new MailTlsInfo
        {
            Check = kind,
            Area = AreaForKind(kind),
            Subject = analysis.Subject ?? string.Empty,
            Servers = servers,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"servers {servers.Count}; valid cert {validCount}/{servers.Count}" + (gradesSummary == string.Empty ? string.Empty : $"; grades A/B/C/D/F: {gradesSummary}"),
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc3207", "https://www.rfc-editor.org/rfc/rfc8314" },
            Raw = analysis
        };
    }
}

public class MailTlsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public IReadOnlyList<MailTlsServerInfo> Servers { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public MailTlsAnalysis Raw { get; set; } = null!;
}

public class MailTlsServerInfo
{
    /// <summary>Server key in the form host:port.</summary>
    public string Key { get; set; } = null!;
    /// <summary>True when STARTTLS was advertised or implicit TLS used.</summary>
    public bool StartTlsAdvertised { get; set; }
    /// <summary>Computed letter grade for TLS posture.</summary>
    public GradeLevel Grade { get; set; }
    /// <summary>True when the leaf certificate is valid (date, host, basic checks).</summary>
    public bool CertificateValid { get; set; }
    /// <summary>True when chain validates without errors.</summary>
    public bool ChainValid { get; set; }
    /// <summary>Days until certificate expiration (negative when expired).</summary>
    public int DaysToExpire { get; set; }
    /// <summary>True when the certificate is expired.</summary>
    public bool IsExpired { get; set; }
    /// <summary>Negotiated TLS protocol.</summary>
    public string Protocol { get; set; } = null!;
    /// <summary>True when server supports TLS 1.3.</summary>
    public bool SupportsTls13 { get; set; }
    /// <summary>True when TLS 1.3 was used for the connection.</summary>
    public bool Tls13Used { get; set; }
    /// <summary>True when certificate hostname matches the server name.</summary>
    public bool HostnameMatch { get; set; }
    /// <summary>Negotiated cipher algorithm.</summary>
    public string CipherAlgorithm { get; set; } = null!;
    /// <summary>Negotiated cipher strength in bits.</summary>
    public int CipherStrength { get; set; }
    /// <summary>Negotiated cipher suite identifier.</summary>
    public string CipherSuite { get; set; } = null!;
    /// <summary>Key exchange algorithm.</summary>
    public string KeyExchangeAlgorithm { get; set; } = null!;
    /// <summary>Diffie-Hellman key size (bits) when applicable.</summary>
    public int DhKeyBits { get; set; }
    /// <summary>Certificate subject (CN/SAN summary).</summary>
    public string CertificateSubject { get; set; } = null!;
    /// <summary>Certificate issuer (legacy field).</summary>
    public string CertificateIssuer { get; set; } = null!;
    /// <summary>Certificate expiration time (legacy field).</summary>
    public System.DateTime? CertificateNotAfter { get; set; }
    /// <summary>Indicator of OCSP stapling (if detected).</summary>
    public bool? OcspStaplingPresent { get; set; }

    // New summary-friendly aliases for scripting/table exports
    /// <summary>Certificate issuer (alias of CertificateIssuer).</summary>
    public string? Issuer { get; set; }
    /// <summary>Certificate validity start (NotBefore).</summary>
    public System.DateTime? ValidFrom { get; set; }
    /// <summary>Certificate validity end (NotAfter).</summary>
    public System.DateTime? ValidTo { get; set; }
    /// <summary>Certificate thumbprint.</summary>
    public string? Thumbprint { get; set; }
}
