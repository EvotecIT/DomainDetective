using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static TlsRptInfo Convert(TLSRPTAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new TlsRptInfo
        {
            Check = HealthCheckType.TLSRPT,
            Area = AreaForKind(HealthCheckType.TLSRPT),
            Subject = analysis.Subject,
            TlsRptRecord = analysis.TlsRptRecord,
            DnsRecordTtl = analysis.DnsRecordTtl,
            CnameTtl = analysis.CnameTtl,
            IsCnameResolved = analysis.IsCnameResolved,
            TlsRptRecordExists = analysis.TlsRptRecordExists,
            MultipleRecords = analysis.MultipleRecords,
            StartsCorrectly = analysis.StartsCorrectly,
            RuaDefined = analysis.RuaDefined,
            MailtoRua = analysis.MailtoRua,
            HttpRua = analysis.HttpRua,
            InvalidRua = analysis.InvalidRua,
            UnknownTags = analysis.UnknownTags,
            PolicyValid = analysis.PolicyValid,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"URIs: mailto {analysis.MailtoRua?.Count ?? 0}, http {analysis.HttpRua?.Count ?? 0}; valid {(analysis.PolicyValid ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides tls rpt info functionality.</summary>
public class TlsRptInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the tls rpt record value.</summary>
    public string? TlsRptRecord { get; set; }
    /// <summary>DNS TTL (seconds) of the TLS-RPT TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the TLSRPT record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    /// <summary>Gets or sets the tls rpt record exists value.</summary>
    public bool TlsRptRecordExists { get; set; }
    /// <summary>Gets or sets the multiple records value.</summary>
    public bool MultipleRecords { get; set; }
    /// <summary>Gets or sets the starts correctly value.</summary>
    public bool StartsCorrectly { get; set; }
    /// <summary>Gets or sets the rua defined value.</summary>
    public bool RuaDefined { get; set; }
    /// <summary>Gets or sets the mailto rua value.</summary>
    public IReadOnlyList<string> MailtoRua { get; set; } = null!;
    /// <summary>Gets or sets the http rua value.</summary>
    public IReadOnlyList<string> HttpRua { get; set; } = null!;
    /// <summary>Gets or sets the invalid rua value.</summary>
    public IReadOnlyList<string> InvalidRua { get; set; } = null!;
    /// <summary>Gets or sets the unknown tags value.</summary>
    public IReadOnlyList<string> UnknownTags { get; set; } = null!;
    /// <summary>Gets or sets the policy valid value.</summary>
    public bool PolicyValid { get; set; }
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
    public TLSRPTAnalysis Raw { get; set; } = null!;
}
