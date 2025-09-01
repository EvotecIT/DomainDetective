using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static MtastsInfo Convert(MTASTSAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new MtastsInfo
        {
            Check = "MTASTS",
            Area = AreaFor("MTASTS"),
            Subject = analysis.Domain,
            DnsRecordPresent = analysis.DnsRecordPresent,
            DnsRecordValid = analysis.DnsRecordValid,
            PolicyPresent = analysis.PolicyPresent,
            PolicyValid = analysis.PolicyValid,
            Mode = analysis.Mode,
            MaxAge = analysis.MaxAge,
            HasMx = analysis.HasMx,
            MxAligned = analysis.MxAligned,
            MissingMxFromPolicy = analysis.MissingMxFromPolicy?.ToArray() ?? System.Array.Empty<string>(),
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"mode {(analysis.Mode ?? "?")}; max-age {analysis.MaxAge}; DNS {(analysis.DnsRecordPresent ? "yes" : "no")}; valid {(analysis.PolicyValid ? "yes" : "no")}; MX aligned {(analysis.MxAligned ? "yes" : "no")}",
            Recommendations = recs,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class MtastsInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public bool DnsRecordPresent { get; set; }
    public bool DnsRecordValid { get; set; }
    public bool PolicyPresent { get; set; }
    public bool PolicyValid { get; set; }
    public string Mode { get; set; }
    public int MaxAge { get; set; }
    public bool HasMx { get; set; }
    public bool MxAligned { get; set; }
    public string[] MissingMxFromPolicy { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public MTASTSAnalysis Raw { get; set; }
}

