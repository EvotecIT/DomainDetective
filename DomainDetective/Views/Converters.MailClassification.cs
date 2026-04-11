using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides mail classification info functionality.</summary>
public sealed class MailClassificationInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the classification value.</summary>
    public string Classification { get; set; } = null!;
    /// <summary>Gets or sets the confidence value.</summary>
    public string Confidence { get; set; } = null!;
    /// <summary>Gets or sets the receiving signals value.</summary>
    public IReadOnlyList<string> ReceivingSignals { get; set; } = null!;
    /// <summary>Gets or sets the sending signals value.</summary>
    public IReadOnlyList<string> SendingSignals { get; set; } = null!;
    /// <summary>Gets or sets the score value.</summary>
    public double Score { get; set; }
    /// <summary>Gets or sets the score breakdown value.</summary>
    public IReadOnlyDictionary<string, double> ScoreBreakdown { get; set; } = null!;
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
    public MailDomainClassificationResult Raw { get; set; } = null!;
    /// <summary>Gets or sets the provider primary value.</summary>
    public string? ProviderPrimary { get; set; }
    /// <summary>Gets or sets the provider gateways value.</summary>
    public IReadOnlyList<string> ProviderGateways { get; set; } = null!;
    /// <summary>Gets or sets the provider outbound value.</summary>
    public IReadOnlyList<string> ProviderOutbound { get; set; } = null!;
}

