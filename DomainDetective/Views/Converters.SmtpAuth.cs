using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SmtpAuthInfo Convert(SmtpAuthAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        var servers = new List<SmtpAuthServerInfo>();
        foreach (var kv in analysis.ServerMechanisms)
        {
            analysis.ServerCapabilities.TryGetValue(kv.Key, out var caps);
            servers.Add(new SmtpAuthServerInfo
            {
                Key = kv.Key,
                Mechanisms = kv.Value ?? System.Array.Empty<string>(),
                Capabilities = caps ?? System.Array.Empty<string>()
            });
        }
        int mechSum = 0;
        foreach (var s in servers)
        {
            mechSum += s.Mechanisms?.Count ?? 0;
        }
        int avg = servers.Count == 0 ? 0 : (int)System.Math.Round((double)mechSum / servers.Count);
        return new SmtpAuthInfo
        {
            Check = HealthCheckType.SMTPAUTH,
            Area = AreaForKind(HealthCheckType.SMTPAUTH),
            Subject = analysis.Subject,
            Servers = servers,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"servers {servers.Count}; mechanisms avg {avg}",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4954", "https://www.rfc-editor.org/rfc/rfc6152" },
            Raw = analysis
        };
    }
}

public class SmtpAuthInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<SmtpAuthServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SmtpAuthAnalysis Raw { get; set; }
}

public class SmtpAuthServerInfo
{
    public string Key { get; set; }
    public IReadOnlyList<string> Mechanisms { get; set; }
    public IReadOnlyList<string> Capabilities { get; set; }
}
