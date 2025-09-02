using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SpfRecordInfo Convert(SpfAnalysis analysis)
    {
        var recs = RecommendationEngine.From(analysis.Assessments);
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        // Build provider summary from part analyses
        var providerCounts = new Dictionary<string, int>(System.StringComparer.OrdinalIgnoreCase);
        if (analysis.SpfPartAnalyses != null)
        {
            foreach (var p in analysis.SpfPartAnalyses)
            {
                if (!string.IsNullOrWhiteSpace(p.Provider))
                {
                    providerCounts[p.Provider!] = providerCounts.TryGetValue(p.Provider!, out var c) ? c + 1 : 1;
                }
            }
        }
        var policy = string.IsNullOrWhiteSpace(analysis.AllMechanism) ? "none" : analysis.AllMechanism.ToLowerInvariant();
        return new SpfRecordInfo
        {
            Check = HealthCheckType.SPF,
            Area = AreaForKind(HealthCheckType.SPF),
            Subject = analysis.Subject,
            SpfRecord = analysis.SpfRecord,
            RecordLength = analysis?.SpfRecord?.Length ?? 0,
            SpfRecordExists = analysis.SpfRecordExists,
            StartsCorrectly = analysis.StartsCorrectly,
            MultipleSpfRecords = analysis.MultipleSpfRecords,
            DnsLookupsCount = analysis.DnsLookupsCount,
            ExceedsDnsLookups = analysis.ExceedsDnsLookups,
            MultipleAllMechanisms = analysis.MultipleAllMechanisms,
            ExceedsTotalCharacterLimit = analysis.ExceedsTotalCharacterLimit,
            ExceedsCharacterLimit = analysis.ExceedsCharacterLimit,
            UnknownMechanisms = analysis.UnknownMechanisms,
            Mechanisms = analysis.SpfPartAnalyses,
            ProviderCounts = providerCounts,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"policy {policy}; lookups {analysis.DnsLookupsCount}/10; size {(analysis.ExceedsTotalCharacterLimit || analysis.ExceedsCharacterLimit ? "limit" : "ok")}",
            Recommendations = recs,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

public class SpfRecordInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public string SpfRecord { get; set; }
    public int RecordLength { get; set; }
    public bool SpfRecordExists { get; set; }
    public bool StartsCorrectly { get; set; }
    public bool MultipleSpfRecords { get; set; }
    public int DnsLookupsCount { get; set; }
    public bool ExceedsDnsLookups { get; set; }
    public bool MultipleAllMechanisms { get; set; }
    public bool ExceedsTotalCharacterLimit { get; set; }
    public bool ExceedsCharacterLimit { get; set; }
    public IReadOnlyList<string> UnknownMechanisms { get; set; }
    public IReadOnlyList<SpfPartAnalysis> Mechanisms { get; set; }
    public IReadOnlyDictionary<string, int> ProviderCounts { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SpfAnalysis Raw { get; set; }
}
