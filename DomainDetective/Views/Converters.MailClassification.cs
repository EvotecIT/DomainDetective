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
        if (result.ReceivingSignals != null && result.SendingSignals != null)
        {
            summary += $"; recv {result.ReceivingSignals.Count}; send {result.SendingSignals.Count}";
        }
        return new MailClassificationInfo
        {
            Check = HealthCheckType.MAILCLASSIFICATION,
            Area = AreaForKind(HealthCheckType.MAILCLASSIFICATION),
            Subject = result.Domain,
            Classification = result.Classification.ToString(),
            Confidence = result.Confidence.ToString(),
            ReceivingSignals = result.ReceivingSignals,
            SendingSignals = result.SendingSignals,
            Score = result.Score,
            ScoreBreakdown = result.ScoreBreakdown,
            Assessments = result.Assessments ?? new List<Assessment>(),
            Status = status,
            WarningCount = warn,
            ErrorCount = err,
            Summary = summary,
            Recommendations = RecommendationEngine.From(result.Assessments ?? new List<Assessment>()),
            References = BuildReferences(result.RfcReferences, new List<RecommendationAdvice>()),
            Raw = result
        };
    }
}

public sealed class MailClassificationInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string Classification { get; set; }
    public string Confidence { get; set; }
    public IReadOnlyList<string> ReceivingSignals { get; set; }
    public IReadOnlyList<string> SendingSignals { get; set; }
    public double Score { get; set; }
    public IReadOnlyDictionary<string, double> ScoreBreakdown { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MailDomainClassificationResult Raw { get; set; }
}

