using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class MtastsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public bool DnsRecordPresent { get; set; }
    public bool DnsRecordValid { get; set; }
    /// <summary>DNS TTL (seconds) of the _mta-sts TXT record.</summary>
    public int? DnsRecordTtl { get; set; }
    /// <summary>TTL (seconds) of the CNAME record when resolved via CNAME alias.</summary>
    public int? CnameTtl { get; set; }
    /// <summary>True when the MTA-STS TXT record was resolved through a CNAME alias.</summary>
    public bool IsCnameResolved { get; set; }
    public string PolicyId { get; set; } = string.Empty;
    public bool PolicyPresent { get; set; }
    public bool PolicyFetchSkipped { get; set; }
    public string PolicyText { get; set; } = string.Empty;
    public bool PolicyValid { get; set; }
    public string Mode { get; set; } = null!;
    public int MaxAge { get; set; }
    public bool EnforcesMtaSts { get; set; }
    public bool HasDuplicateFields { get; set; }
    public bool HasMx { get; set; }
    public IReadOnlyList<string> MxPatterns { get; set; } = System.Array.Empty<string>();
    public bool MxAligned { get; set; }
    public string[] MissingMxFromPolicy { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    [JsonIgnore]
    public MTASTSAnalysis Raw { get; set; } = null!;
}
