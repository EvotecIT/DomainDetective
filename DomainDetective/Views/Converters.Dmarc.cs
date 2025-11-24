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
            DnsRecordTtl = analysis.DnsRecordTtl,
            DnsRecordTtls = analysis.DnsRecordTtls,
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

/// <summary>
/// View model summarizing DMARC policy analysis for reporting.
/// </summary>
public class DmarcRecordInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Raw DMARC TXT record.</summary>
    public string DmarcRecord { get; set; } = string.Empty;
    /// <summary>Minimum TTL across DMARC TXT answers.</summary>
    public int? DnsRecordTtl { get; set; }
    public IReadOnlyList<int> DnsRecordTtls { get; set; } = System.Array.Empty<int>();
    public bool DmarcRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool IsPolicyValid { get; set; }
    /// <summary>Policy (p=).</summary>
    public string Policy { get; set; } = string.Empty;
    /// <summary>Subdomain policy (sp=).</summary>
    public string SubPolicy { get; set; } = string.Empty;
    /// <summary>Nonexistent domain policy (np=, DMARCbis).</summary>
    public string NonexistentPolicy { get; set; } = string.Empty;
    /// <summary>Public suffix policy (psd=, DMARCbis).</summary>
    public string PublicSuffixPolicy { get; set; } = string.Empty;
    /// <summary>Report feedback (rfb=, DMARCbis).</summary>
    public string ReportFeedback { get; set; } = string.Empty;
    /// <summary>Percent of messages to which policy applies.</summary>
    public string Percent { get; set; } = string.Empty;
    /// <summary>DKIM alignment (adkim).</summary>
    public string DkimAlignment { get; set; } = string.Empty;
    /// <summary>SPF alignment (aspf).</summary>
    public string SpfAlignment { get; set; } = string.Empty;
    public string Rua { get; set; } = string.Empty;
    public string Ruf { get; set; } = string.Empty;
    /// <summary>Aggregate report mailto URIs (rua).</summary>
    public IReadOnlyList<string> MailtoRua { get; set; } = System.Array.Empty<string>();
    /// <summary>Aggregate report HTTP URIs (rua).</summary>
    public IReadOnlyList<string> HttpRua { get; set; } = System.Array.Empty<string>();
    /// <summary>Forensic report mailto URIs (ruf).</summary>
    public IReadOnlyList<string> MailtoRuf { get; set; } = System.Array.Empty<string>();
    /// <summary>Forensic report HTTP URIs (ruf).</summary>
    public IReadOnlyList<string> HttpRuf { get; set; } = System.Array.Empty<string>();
    public IReadOnlyDictionary<string, bool> ExternalReportAuthorization { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    public bool InvalidReportUri { get; set; }
    /// <summary>Deprecated tags present in the record.</summary>
    public IReadOnlyList<string> DeprecatedTags { get; set; } = System.Array.Empty<string>();
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    /// <summary>Short summary text for executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public DmarcAnalysis Raw { get; set; } = new DmarcAnalysis();
    /// <summary>Narrative (human-friendly) content blocks.</summary>
    public DomainDetective.Narratives.DmarcNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DmarcNarrative.Sections();
    /// <summary>Key highlights extracted for the report.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
}
