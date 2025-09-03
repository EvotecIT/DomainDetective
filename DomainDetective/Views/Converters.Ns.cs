using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static NsInfo Convert(NSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new NsInfo
        {
            Check = HealthCheckType.NS,
            Area = AreaForKind(HealthCheckType.NS),
            Subject = analysis.Subject, // if null, leave null
            NsRecords = analysis.NsRecords,
            NsRecordExists = analysis.NsRecordExists,
            HasDuplicates = analysis.HasDuplicates,
            AtLeastTwoRecords = analysis.AtLeastTwoRecords,
            AllHaveAOrAaaa = analysis.AllHaveAOrAaaa,
            PointsToCname = analysis.PointsToCname,
            HasDiverseLocations = analysis.HasDiverseLocations,
            ParentNsRecords = analysis.ParentNsRecords,
            DelegationMatches = analysis.DelegationMatches,
            GlueRecordsComplete = analysis.GlueRecordsComplete,
            GlueRecordsConsistent = analysis.GlueRecordsConsistent,
            RootServerResponses = analysis.RootServerResponses,
            RecursionEnabled = analysis.RecursionEnabled,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{analysis.NsRecords?.Count ?? 0} NS; glue {(analysis.GlueRecordsComplete ? "complete" : "incomplete")}/{(analysis.GlueRecordsConsistent ? "consistent" : "mixed")}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

public class NsInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<string> NsRecords { get; set; }
    public bool NsRecordExists { get; set; }
    public bool HasDuplicates { get; set; }
    public bool AtLeastTwoRecords { get; set; }
    public bool AllHaveAOrAaaa { get; set; }
    public bool PointsToCname { get; set; }
    public bool HasDiverseLocations { get; set; }
    public IReadOnlyList<string> ParentNsRecords { get; set; }
    public bool DelegationMatches { get; set; }
    public bool GlueRecordsComplete { get; set; }
    public bool GlueRecordsConsistent { get; set; }
    public IReadOnlyDictionary<string, bool> RootServerResponses { get; set; }
    public IReadOnlyDictionary<string, bool> RecursionEnabled { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public NSAnalysis Raw { get; set; }
}
