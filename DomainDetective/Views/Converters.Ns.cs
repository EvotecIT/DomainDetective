using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static NsInfo Convert(NSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new NsInfo
        {
            Check = "NS",
            Subject = null, // NSAnalysis does not track subject explicitly
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
            Recommendations = recs,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

public class NsInfo
{
    public string Check { get; set; }
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
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public NSAnalysis Raw { get; set; }
}

