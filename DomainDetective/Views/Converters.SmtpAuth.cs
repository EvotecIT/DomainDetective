using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static SmtpAuthInfo Convert(SmtpAuthAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
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
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4954", "https://www.rfc-editor.org/rfc/rfc6152" },
            Raw = analysis
        };
    }
}

/// <summary>Provides smtp auth info functionality.</summary>
public class SmtpAuthInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyList<SmtpAuthServerInfo> Servers { get; set; } = null!;
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
    public SmtpAuthAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides smtp auth server info functionality.</summary>
public class SmtpAuthServerInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Gets or sets the mechanisms value.</summary>
    public IReadOnlyList<string> Mechanisms { get; set; } = null!;
    /// <summary>Gets or sets the capabilities value.</summary>
    public IReadOnlyList<string> Capabilities { get; set; } = null!;
}
