using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SpfRecordInfo Convert(SpfAnalysis analysis)
    {
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new SpfRecordInfo
        {
            SpfRecord = analysis.SpfRecord,
            SpfRecordExists = analysis.SpfRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            MultipleSpfRecords = analysis.MultipleSpfRecords,
            DnsLookupsCount = analysis.DnsLookupsCount,
            ExceedsDnsLookups = analysis.ExceedsDnsLookups,
            MultipleAllMechanisms = analysis.MultipleAllMechanisms,
            ExceedsTotalCharacterLimit = analysis.ExceedsTotalCharacterLimit,
            ExceedsCharacterLimit = analysis.ExceedsCharacterLimit,
            UnknownMechanisms = analysis.UnknownMechanisms,
            Advisory = analysis.Advisory,
            Warnings = analysis.Warnings,
            Assessments = analysis.Assessments,
            Recommendations = recs,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class SpfRecordInfo
{
    public string SpfRecord { get; set; }
    public bool SpfRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool MultipleSpfRecords { get; set; }
    public int DnsLookupsCount { get; set; }
    public bool ExceedsDnsLookups { get; set; }
    public bool MultipleAllMechanisms { get; set; }
    public bool ExceedsTotalCharacterLimit { get; set; }
    public bool ExceedsCharacterLimit { get; set; }
    public IReadOnlyList<string> UnknownMechanisms { get; set; }
    public string Advisory { get; set; }
    public IReadOnlyList<string> Warnings { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SpfAnalysis Raw { get; set; }
}

