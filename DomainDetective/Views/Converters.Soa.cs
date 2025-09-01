using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SoaInfo Convert(SOAAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new SoaInfo
        {
            Check = "SOA",
            Area = AreaFor("SOA"),
            Subject = analysis.Subject ?? analysis.DomainName,
            PrimaryNameServer = analysis.PrimaryNameServer,
            ResponsibleMailbox = analysis.ResponsibleMailbox,
            SerialNumber = analysis.SerialNumber,
            SerialFormatValid = analysis.SerialFormatValid,
            SerialFormatSuggestion = analysis.SerialFormatSuggestion,
            Refresh = analysis.Refresh,
            Retry = analysis.Retry,
            Expire = analysis.Expire,
            Minimum = analysis.Minimum,
            NegativeCacheTtl = analysis.NegativeCacheTtl,
            RecordExists = analysis.RecordExists,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"serial {analysis.SerialNumber} ({(analysis.SerialFormatValid ? "valid" : "check")}); refresh {analysis.Refresh}s",
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Raw = analysis
        };
    }
}

public class SoaInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public string PrimaryNameServer { get; set; }
    public string ResponsibleMailbox { get; set; }
    public long SerialNumber { get; set; }
    public bool SerialFormatValid { get; set; }
    public string SerialFormatSuggestion { get; set; }
    public int Refresh { get; set; }
    public int Retry { get; set; }
    public int Expire { get; set; }
    public int Minimum { get; set; }
    public int NegativeCacheTtl { get; set; }
    public bool RecordExists { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SOAAnalysis Raw { get; set; }
}
