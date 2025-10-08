using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DmarcRecordInfo Convert(DmarcAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var narrative = DomainDetective.Narratives.DmarcNarrative.Build(analysis);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new DmarcRecordInfo
        {
            Check = HealthCheckType.DMARC,
            Area = AreaForKind(HealthCheckType.DMARC),
            Subject = analysis.Subject,
            DmarcRecord = analysis.DmarcRecord,
            DmarcRecordExists = analysis.DmarcRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            IsPolicyValid = analysis.IsPolicyValid,
            Policy = analysis.Policy,
            SubPolicy = analysis.SubPolicy,
            NonexistentPolicy = analysis.NonexistentPolicy,
            PublicSuffixPolicy = analysis.PublicSuffixPolicy,
            ReportFeedback = analysis.ReportFeedback,
            Percent = analysis.Percent,
            DkimAlignment = analysis.DkimAlignment,
            SpfAlignment = analysis.SpfAlignment,
            Rua = analysis.Rua,
            Ruf = analysis.Ruf,
            MailtoRua = analysis.MailtoRua,
            HttpRua = analysis.HttpRua,
            MailtoRuf = analysis.MailtoRuf,
            HttpRuf = analysis.HttpRuf,
            ExternalReportAuthorization = analysis.ExternalReportAuthorization,
            InvalidReportUri = analysis.InvalidReportUri,
            DeprecatedTags = analysis.DeprecatedTags,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"p={analysis.Policy ?? "?"}; rua {analysis.MailtoRua?.Count ?? 0}; align dkim={analysis.DkimAlignment ?? "?"}/spf={analysis.SpfAlignment ?? "?"}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis,
            Narrative = narrative,
            Highlights = narrative.Highlights
        };
    }
}

public class DmarcRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string DmarcRecord { get; set; } = string.Empty;
    public bool DmarcRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool IsPolicyValid { get; set; }
    public string Policy { get; set; } = string.Empty;
    public string SubPolicy { get; set; } = string.Empty;
    public string NonexistentPolicy { get; set; } = string.Empty;
    public string PublicSuffixPolicy { get; set; } = string.Empty;
    public string ReportFeedback { get; set; } = string.Empty;
    public string Percent { get; set; } = string.Empty;
    public string DkimAlignment { get; set; } = string.Empty;
    public string SpfAlignment { get; set; } = string.Empty;
    public string Rua { get; set; } = string.Empty;
    public string Ruf { get; set; } = string.Empty;
    public IReadOnlyList<string> MailtoRua { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> HttpRua { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> MailtoRuf { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> HttpRuf { get; set; } = System.Array.Empty<string>();
    public IReadOnlyDictionary<string, bool> ExternalReportAuthorization { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    public bool InvalidReportUri { get; set; }
    public IReadOnlyList<string> DeprecatedTags { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DmarcAnalysis Raw { get; set; } = new DmarcAnalysis();
    public DomainDetective.Narratives.DmarcNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DmarcNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
}
