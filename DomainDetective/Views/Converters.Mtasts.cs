using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static MtastsInfo Convert(MTASTSAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new MtastsInfo
        {
            Check = HealthCheckType.MTASTS,
            Area = AreaForKind(HealthCheckType.MTASTS),
            Subject = analysis.Domain,
            DnsRecordPresent = analysis.DnsRecordPresent,
            DnsRecordValid = analysis.DnsRecordValid,
            DnsRecordTtl = analysis.DnsRecordTtl,
            CnameTtl = analysis.CnameTtl,
            IsCnameResolved = analysis.IsCnameResolved,
            PolicyId = analysis.PolicyId,
            PolicyPresent = analysis.PolicyPresent,
            PolicyFetchSkipped = analysis.PolicyFetchSkipped,
            PolicyText = analysis.Policy,
            PolicyValid = analysis.PolicyValid,
            Mode = analysis.Mode,
            MaxAge = analysis.MaxAge,
            EnforcesMtaSts = analysis.EnforcesMtaSts,
            HasDuplicateFields = analysis.HasDuplicateFields,
            HasMx = analysis.HasMx,
            MxPatterns = analysis.Mx?.ToArray() ?? System.Array.Empty<string>(),
            MxAligned = analysis.MxAligned,
            MissingMxFromPolicy = analysis.MissingMxFromPolicy?.ToArray() ?? System.Array.Empty<string>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = analysis.PolicyFetchSkipped
                ? $"DNS {(analysis.DnsRecordPresent ? "yes" : "no")}; bootstrap valid {(analysis.DnsRecordValid ? "yes" : "no")}; policy fetch skipped in this pass"
                : $"mode {(analysis.Mode ?? "?")}; max-age {analysis.MaxAge}; DNS {(analysis.DnsRecordPresent ? "yes" : "no")}; valid {(analysis.PolicyValid ? "yes" : "no")}; MX aligned {(analysis.MxAligned ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides mtasts info functionality.</summary>
public class MtastsInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the dns record present value.</summary>
    public bool DnsRecordPresent { get; set; }
    /// <summary>Gets or sets the dns record valid value.</summary>
    public bool DnsRecordValid { get; set; }
    /// <summary>DNS TTL (seconds) of the _mta-sts TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the MTA-STS TXT record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    /// <summary>Gets or sets the policy id value.</summary>
    public string PolicyId { get; set; } = string.Empty;
    /// <summary>Gets or sets the policy present value.</summary>
    public bool PolicyPresent { get; set; }
    /// <summary>Gets or sets the policy fetch skipped value.</summary>
    public bool PolicyFetchSkipped { get; set; }
    /// <summary>Gets or sets the policy text value.</summary>
    public string PolicyText { get; set; } = string.Empty;
    /// <summary>Gets or sets the policy valid value.</summary>
    public bool PolicyValid { get; set; }
    /// <summary>Gets or sets the mode value.</summary>
    public string Mode { get; set; } = null!;
    /// <summary>Gets or sets the max age value.</summary>
    public int MaxAge { get; set; }
    /// <summary>Gets or sets the enforces mta sts value.</summary>
    public bool EnforcesMtaSts { get; set; }
    /// <summary>Gets or sets the has duplicate fields value.</summary>
    public bool HasDuplicateFields { get; set; }
    /// <summary>Gets or sets the has mx value.</summary>
    public bool HasMx { get; set; }
    /// <summary>Gets or sets the mx patterns value.</summary>
    public IReadOnlyList<string> MxPatterns { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the mx aligned value.</summary>
    public bool MxAligned { get; set; }
    /// <summary>Gets or sets the missing mx from policy value.</summary>
    public string[] MissingMxFromPolicy { get; set; } = System.Array.Empty<string>();
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
    [JsonIgnore]
    public MTASTSAnalysis Raw { get; set; } = null!;
}
