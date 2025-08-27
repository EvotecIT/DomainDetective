using System.Collections.Generic;

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
        return new SmtpAuthInfo
        {
            Check = "SMTPAUTH",
            Subject = analysis.Subject,
            Servers = servers,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4954", "https://www.rfc-editor.org/rfc/rfc6152" },
            Raw = analysis
        };
    }
}

public class SmtpAuthInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<SmtpAuthServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
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

