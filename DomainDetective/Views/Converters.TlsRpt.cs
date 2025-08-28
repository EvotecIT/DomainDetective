using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static TlsRptInfo Convert(TLSRPTAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new TlsRptInfo
        {
            Check = "TLSRPT",
            Subject = null,
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
            Recommendations = recs,
            References = analysis.RfcReferences,
            Raw = analysis
        };
    }
}

public class TlsRptInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public string TlsRptRecord { get; set; }
    public bool TlsRptRecordExists { get; set; }
    public bool MultipleRecords { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool RuaDefined { get; set; }
    public IReadOnlyList<string> MailtoRua { get; set; }
    public IReadOnlyList<string> HttpRua { get; set; }
    public IReadOnlyList<string> InvalidRua { get; set; }
    public IReadOnlyList<string> UnknownTags { get; set; }
    public bool PolicyValid { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public TLSRPTAnalysis Raw { get; set; }
}

