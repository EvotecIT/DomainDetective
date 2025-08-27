using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MailTlsInfo Convert(SMTPTLSAnalysis analysis) => ConvertCore(analysis, "SMTPTLS");
    public static MailTlsInfo Convert(IMAPTLSAnalysis analysis) => ConvertCore(analysis, "IMAPTLS");
    public static MailTlsInfo Convert(POP3TLSAnalysis analysis) => ConvertCore(analysis, "POP3TLS");

    private static MailTlsInfo ConvertCore(MailTlsAnalysis analysis, string check)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var servers = new List<MailTlsServerInfo>();
        foreach (var kv in analysis.ServerResults)
        {
            var r = kv.Value;
            servers.Add(new MailTlsServerInfo
            {
                Key = kv.Key,
                StartTlsAdvertised = r.StartTlsAdvertised,
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
                DhKeyBits = r.DhKeyBits,
                CertificateSubject = r.CertificateSubject,
                CertificateIssuer = r.CertificateIssuer,
                CertificateNotAfter = r.CertificateNotAfter
            });
        }
        return new MailTlsInfo
        {
            Check = check,
            Subject = null,
            Servers = servers,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc3207", "https://www.rfc-editor.org/rfc/rfc8314" },
            Raw = analysis
        };
    }
}

public class MailTlsInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<MailTlsServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MailTlsAnalysis Raw { get; set; }
}

public class MailTlsServerInfo
{
    public string Key { get; set; }
    public bool StartTlsAdvertised { get; set; }
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
    public int DhKeyBits { get; set; }
    public string CertificateSubject { get; set; }
    public string CertificateIssuer { get; set; }
    public System.DateTime? CertificateNotAfter { get; set; }
}

