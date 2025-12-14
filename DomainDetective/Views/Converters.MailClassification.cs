using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MailClassificationInfo Convert(MailDomainClassificationResult result)
    {
        int warn = 0, err = 0; string status = "OK";
        if (result.Assessments != null)
        {
            Summarize(result.Assessments, out warn, out err, out status);
        }
        var summary = $"{result.Classification} ({result.Confidence})";
        if (!string.IsNullOrWhiteSpace(result.ProviderPrimary))
        {
            var gw = (result.ProviderGateways != null && result.ProviderGateways.Count > 0)
                ? $", via {string.Join(", ", result.ProviderGateways)}"
                : string.Empty;
            var ob = (result.ProviderOutbound != null && result.ProviderOutbound.Count > 0)
                ? $"; outbound: {string.Join(", ", result.ProviderOutbound)}"
                : string.Empty;
            summary += $" — provider: {result.ProviderPrimary}{gw}{ob}";
        }
        if (result.ReceivingSignals != null && result.SendingSignals != null)
        {
            summary += $"; recv {result.ReceivingSignals.Count}; send {result.SendingSignals.Count}";
        }
        var assessments = result.Assessments ?? new List<Assessment>();
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new MailClassificationInfo
        {
            Check = HealthCheckType.MAILCLASSIFICATION,
            Area = AreaForKind(HealthCheckType.MAILCLASSIFICATION),
            Subject = result.Domain,
            Classification = result.Classification.ToString(),
            Confidence = result.Confidence.ToString(),
            ReceivingSignals = result.ReceivingSignals ?? System.Array.Empty<string>(),
            SendingSignals = result.SendingSignals ?? System.Array.Empty<string>(),
            Score = result.Score,
            ScoreBreakdown = result.ScoreBreakdown,
            Assessments = assessments,
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(result.RfcReferences, recs),
            Raw = result,
            ProviderPrimary = result.ProviderPrimary,
            ProviderGateways = result.ProviderGateways ?? System.Array.Empty<string>(),
            ProviderOutbound = result.ProviderOutbound ?? System.Array.Empty<string>()
        };
    }
}

public sealed class MailClassificationInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public string Classification { get; set; } = null!;
    public string Confidence { get; set; } = null!;
    public IReadOnlyList<string> ReceivingSignals { get; set; } = null!;
    public IReadOnlyList<string> SendingSignals { get; set; } = null!;
    public double Score { get; set; }
    public IReadOnlyDictionary<string, double> ScoreBreakdown { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public MailDomainClassificationResult Raw { get; set; } = null!;
    public string? ProviderPrimary { get; set; }
    public IReadOnlyList<string> ProviderGateways { get; set; } = null!;
    public IReadOnlyList<string> ProviderOutbound { get; set; } = null!;
}

