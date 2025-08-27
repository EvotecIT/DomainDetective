using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static WildcardDnsInfo Convert(WildcardDnsAnalysis analysis)
    {
        var assessments = (analysis as IHasAssessments)?.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new WildcardDnsInfo
        {
            Check = "WILDCARD",
            Subject = null,
            CatchAll = analysis.CatchAll,
            SoaExists = analysis.SoaExists,
            NsExists = analysis.NsExists,
            TestedNames = analysis.TestedNames,
            ResolvedNames = analysis.ResolvedNames,
            ResolvedAddresses = analysis.ResolvedAddresses,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4592" },
            Raw = analysis
        };
    }
}

public class WildcardDnsInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public bool CatchAll { get; set; }
    public bool SoaExists { get; set; }
    public bool NsExists { get; set; }
    public IReadOnlyList<string> TestedNames { get; set; }
    public IReadOnlyList<string> ResolvedNames { get; set; }
    public IReadOnlyList<string> ResolvedAddresses { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public WildcardDnsAnalysis Raw { get; set; }
}

