using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SmtpBannerInfo Convert(SMTPBannerAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        var servers = new List<SmtpBannerServerInfo>();
        foreach (var kv in analysis.ServerResults)
        {
            var r = kv.Value;
            servers.Add(new SmtpBannerServerInfo
            {
                Key = kv.Key,
                Banner = r?.Banner,
                HostnameMatch = r?.HostnameMatch ?? false,
                SoftwareMatch = r?.SoftwareMatch ?? false,
                StartsWith220 = r?.StartsWith220 ?? false,
                ContainsDomain = r?.ContainsDomain ?? false,
                ValidFormat = r?.ValidFormat ?? false,
                GreetingCode = r?.GreetingCode,
                ServerDomain = r?.ServerDomain,
                Truncated = r?.Truncated ?? false,
                ResponseTimeMs = r?.ResponseTimeMs
            });
        }
        int hostMatch = 0;
        foreach (var s in servers)
        {
            if (s.HostnameMatch) hostMatch++;
        }
        return new SmtpBannerInfo
        {
            Check = HealthCheckType.SMTPBANNER,
            Area = AreaForKind(HealthCheckType.SMTPBANNER),
            Subject = analysis.Subject,
            ExpectedHostname = analysis.ExpectedHostname,
            ExpectedSoftware = analysis.ExpectedSoftware,
            Servers = servers,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"servers {servers.Count}; hostname match {hostMatch}/{servers.Count}",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Raw = analysis
        };
    }
}

public class SmtpBannerInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string ExpectedHostname { get; set; }
    public string ExpectedSoftware { get; set; }
    public IReadOnlyList<SmtpBannerServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SMTPBannerAnalysis Raw { get; set; }
}

public class SmtpBannerServerInfo
{
    public string Key { get; set; }
    public string Banner { get; set; }
    public bool HostnameMatch { get; set; }
    public bool SoftwareMatch { get; set; }
    public bool StartsWith220 { get; set; }
    public bool ContainsDomain { get; set; }
    public bool ValidFormat { get; set; }
    public int? GreetingCode { get; set; }
    public string ServerDomain { get; set; }
    public bool Truncated { get; set; }
    public int? ResponseTimeMs { get; set; }
}
