using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static SmtpBannerInfo Convert(SMTPBannerAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
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
                ResponseTimeMs = r?.ResponseTimeMs,
                TlsAdvertised = r?.TlsAdvertised ?? false
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
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Raw = analysis
        };
    }
}

/// <summary>Provides smtp banner info functionality.</summary>
public class SmtpBannerInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the expected hostname value.</summary>
    public string? ExpectedHostname { get; set; }
    /// <summary>Gets or sets the expected software value.</summary>
    public string? ExpectedSoftware { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyList<SmtpBannerServerInfo> Servers { get; set; } = null!;
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
    public SMTPBannerAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides smtp banner server info functionality.</summary>
public class SmtpBannerServerInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Gets or sets the banner value.</summary>
    public string? Banner { get; set; }
    /// <summary>Gets or sets the hostname match value.</summary>
    public bool HostnameMatch { get; set; }
    /// <summary>Gets or sets the software match value.</summary>
    public bool SoftwareMatch { get; set; }
    /// <summary>Gets or sets the starts with220 value.</summary>
    public bool StartsWith220 { get; set; }
    /// <summary>Gets or sets the contains domain value.</summary>
    public bool ContainsDomain { get; set; }
    /// <summary>Gets or sets the valid format value.</summary>
    public bool ValidFormat { get; set; }
    /// <summary>Gets or sets the greeting code value.</summary>
    public int? GreetingCode { get; set; }
    /// <summary>Gets or sets the server domain value.</summary>
    public string? ServerDomain { get; set; }
    /// <summary>Gets or sets the truncated value.</summary>
    public bool Truncated { get; set; }
    /// <summary>Gets or sets the response time ms value.</summary>
    public int? ResponseTimeMs { get; set; }
    /// <summary>Gets or sets the tls advertised value.</summary>
    public bool TlsAdvertised { get; set; }
}
