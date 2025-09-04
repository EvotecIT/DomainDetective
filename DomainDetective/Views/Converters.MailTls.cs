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
                KeyExchangeAlgorithm = r.KeyExchangeAlgorithm,
                DhKeyBits = r.DhKeyBits,
                CertificateSubject = r.CertificateSubject,
                CertificateIssuer = r.CertificateIssuer,
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
            Subject = analysis.Subject,
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
    public string Subject { get; set; }
    public IReadOnlyList<MailTlsServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MailTlsAnalysis Raw { get; set; }
}

public class MailTlsServerInfo
{
    public string Key { get; set; }
    public bool StartTlsAdvertised { get; set; }
    public GradeLevel Grade { get; set; }
    public bool CertificateValid { get; set; }
    public bool ChainValid { get; set; }
    public int DaysToExpire { get; set; }
    public bool IsExpired { get; set; }
    public string Protocol { get; set; }
    public bool SupportsTls13 { get; set; }
    public bool Tls13Used { get; set; }
    public bool HostnameMatch { get; set; }
    public string CipherAlgorithm { get; set; }
    public int CipherStrength { get; set; }
    public string CipherSuite { get; set; }
    public string KeyExchangeAlgorithm { get; set; }
    public int DhKeyBits { get; set; }
    public string CertificateSubject { get; set; }
    public string CertificateIssuer { get; set; }
    public System.DateTime? CertificateNotAfter { get; set; }
    public bool? OcspStaplingPresent { get; set; }
}
