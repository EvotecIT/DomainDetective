using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static AutodiscoverInfo Convert(AutodiscoverAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new AutodiscoverInfo
        {
            Check = "AUTODISCOVER",
            Area = AreaFor("AUTODISCOVER"),
            Subject = null,
            SrvRecordExists = analysis.SrvRecordExists,
            SrvTarget = analysis.SrvTarget,
            SrvPort = analysis.SrvPort,
            AutoconfigCnameExists = analysis.AutoconfigCnameExists,
            AutoconfigTarget = analysis.AutoconfigTarget,
            AutodiscoverCnameExists = analysis.AutodiscoverCnameExists,
            AutodiscoverTarget = analysis.AutodiscoverTarget,
            Endpoints = analysis.Endpoints,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"SRV {(analysis.SrvRecordExists?"yes":"no")}; CNAME {(analysis.AutodiscoverCnameExists?"yes":"no")}",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class AutodiscoverInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public bool SrvRecordExists { get; set; }
    public string SrvTarget { get; set; }
    public int SrvPort { get; set; }
    public bool AutoconfigCnameExists { get; set; }
    public string AutoconfigTarget { get; set; }
    public bool AutodiscoverCnameExists { get; set; }
    public string AutodiscoverTarget { get; set; }
    public IReadOnlyList<AutodiscoverEndpointResult> Endpoints { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public AutodiscoverAnalysis Raw { get; set; }
}
