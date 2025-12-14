using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class TlsRptInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public string? TlsRptRecord { get; set; }
    public bool TlsRptRecordExists { get; set; }
    public bool MultipleRecords { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool RuaDefined { get; set; }
    public IReadOnlyList<string> MailtoRua { get; set; } = null!;
    public IReadOnlyList<string> HttpRua { get; set; } = null!;
    public IReadOnlyList<string> InvalidRua { get; set; } = null!;
    public IReadOnlyList<string> UnknownTags { get; set; } = null!;
    public bool PolicyValid { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public TLSRPTAnalysis Raw { get; set; } = null!;
}
