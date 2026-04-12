using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
            Subject = analysis.Subject ?? string.Empty,
            DmarcRecord = analysis.DmarcRecord,
            DnsRecordTtl = analysis.DnsRecordTtl,
            CnameTtl = analysis.CnameTtl,
            IsCnameResolved = analysis.IsCnameResolved,
            DmarcRecordExists = analysis.DmarcRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            IsPolicyValid = analysis.IsPolicyValid,
            Policy = analysis.Policy,
            SubPolicy = analysis.SubPolicy,
            NonexistentPolicy = analysis.NonexistentPolicy,
            PublicSuffixPolicy = analysis.PublicSuffixPolicy,
            ReportFeedback = analysis.ReportFeedback,
            Pct = analysis.Pct,
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
            UnknownTags = analysis.UnknownTags,
            MultipleRecords = analysis.MultipleRecords,
            ExceedsCharacterLimit = analysis.ExceedsCharacterLimit,
            HasMandatoryTags = analysis.HasMandatoryTags,
            ValidDkimAlignment = analysis.ValidDkimAlignment,
            ValidSpfAlignment = analysis.ValidSpfAlignment,
            WeakPolicy = analysis.WeakPolicy,
            PolicyRecommendation = analysis.PolicyRecommendation,
            Advisory = analysis.Advisory,
            SpfAligned = analysis.SpfAligned,
            DkimAligned = analysis.DkimAligned,
            IsPctValid = analysis.IsPctValid,
            OriginalPct = analysis.OriginalPct,
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
            Highlights = narrative.Highlights,
            Details = narrative.Details,
            UnauthorizedExternalReportDomains = analysis.ExternalReportAuthorization
                .Where(static entry => !entry.Value)
                .Select(static entry => entry.Key)
                .OrderBy(static entry => entry, System.StringComparer.OrdinalIgnoreCase)
                .ToArray()
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
    /// <summary>DNS TTL (seconds) of the DMARC TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the DMARC record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    /// <summary>Gets or sets the dmarc record exists value.</summary>
    public bool DmarcRecordExists { get; set; }
    /// <summary>Gets or sets the starts correctly value.</summary>
    public bool StartsCorrectly { get; set; }
    /// <summary>Gets or sets the is policy valid value.</summary>
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
    /// <summary>Numeric percent (pct=) value when available.</summary>
    public int? Pct { get; set; }
    /// <summary>DKIM alignment (adkim).</summary>
    public string DkimAlignment { get; set; } = string.Empty;
    /// <summary>SPF alignment (aspf).</summary>
    public string SpfAlignment { get; set; } = string.Empty;
    /// <summary>Gets or sets the rua value.</summary>
    public string Rua { get; set; } = string.Empty;
    /// <summary>Gets or sets the ruf value.</summary>
    public string Ruf { get; set; } = string.Empty;
    /// <summary>Aggregate report mailto URIs (rua).</summary>
    public IReadOnlyList<string> MailtoRua { get; set; } = System.Array.Empty<string>();
    /// <summary>Aggregate report HTTP URIs (rua).</summary>
    public IReadOnlyList<string> HttpRua { get; set; } = System.Array.Empty<string>();
    /// <summary>Forensic report mailto URIs (ruf).</summary>
    public IReadOnlyList<string> MailtoRuf { get; set; } = System.Array.Empty<string>();
    /// <summary>Forensic report HTTP URIs (ruf).</summary>
    public IReadOnlyList<string> HttpRuf { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the external report authorization value.</summary>
    public IReadOnlyDictionary<string, bool> ExternalReportAuthorization { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    /// <summary>Gets or sets the unauthorized external report domains value.</summary>
    public IReadOnlyList<string> UnauthorizedExternalReportDomains { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the invalid report uri value.</summary>
    public bool InvalidReportUri { get; set; }
    /// <summary>Deprecated tags present in the record.</summary>
    public IReadOnlyList<string> DeprecatedTags { get; set; } = System.Array.Empty<string>();
    /// <summary>Unknown tags present in the record.</summary>
    public IReadOnlyList<string> UnknownTags { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the multiple records value.</summary>
    public bool MultipleRecords { get; set; }
    /// <summary>Gets or sets the exceeds character limit value.</summary>
    public bool ExceedsCharacterLimit { get; set; }
    /// <summary>Gets or sets the has mandatory tags value.</summary>
    public bool HasMandatoryTags { get; set; }
    /// <summary>Gets or sets the valid dkim alignment value.</summary>
    public bool ValidDkimAlignment { get; set; }
    /// <summary>Gets or sets the valid spf alignment value.</summary>
    public bool ValidSpfAlignment { get; set; }
    /// <summary>Gets or sets the weak policy value.</summary>
    public bool WeakPolicy { get; set; }
    /// <summary>Gets or sets the policy recommendation value.</summary>
    public string? PolicyRecommendation { get; set; }
    /// <summary>Gets or sets the advisory value.</summary>
    public string Advisory { get; set; } = string.Empty;
    /// <summary>Gets or sets the spf aligned value.</summary>
    public bool SpfAligned { get; set; }
    /// <summary>Gets or sets the dkim aligned value.</summary>
    public bool DkimAligned { get; set; }
    /// <summary>Gets or sets the is pct valid value.</summary>
    public bool IsPctValid { get; set; }
    /// <summary>Gets or sets the original pct value.</summary>
    public int? OriginalPct { get; set; }
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
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
    /// <summary>Supporting narrative details extracted for the report.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
}
