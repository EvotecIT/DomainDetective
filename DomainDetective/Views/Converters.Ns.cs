using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    private static AggregateCheckStatusInfo BuildNsStatus(NsInfo info) => new() {
        Key = "ns", Label = "NS",
        State = !info.NsLookupComplete ? AggregateCheckState.Unknown : !info.NsRecordExists || info.ErrorCount > 0
            ? AggregateCheckState.Fail : info.DnsQueryFailed || info.WarningCount > 0 || !info.AtLeastTwoRecords
            ? AggregateCheckState.Warning : AggregateCheckState.Pass,
        Value = !info.NsLookupComplete ? "Unknown" : info.NsRecordExists ? $"{info.NsRecords.Count} nameserver(s)" : "Missing",
        Detail = !info.NsLookupComplete ? "NS discovery did not complete; record presence is unknown."
            : info.DnsQueryFailed ? "Some nameserver DNS evidence remains incomplete."
            : info.NsRecordExists ? $"ASN diversity: {info.AsnDistinctCount}" : "No authoritative nameservers published."
    };

    /// <summary>Executes the convert operation.</summary>
    public static NsInfo Convert(NSAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        return new NsInfo
        {
            Check = HealthCheckType.NS,
            Area = AreaForKind(HealthCheckType.NS),
            Subject = analysis.Subject ?? string.Empty,
            NsRecords = analysis.NsRecords,
            NsRecordExists = analysis.NsRecordExists,
            NsLookupComplete = analysis.NsLookupComplete,
            DnsQueryFailed = analysis.DnsQueryFailed,
            DnsQueryErrors = analysis.DnsQueryErrors,
            DelegationAnalysisComplete = analysis.DelegationAnalysisComplete,
            HasDuplicates = analysis.HasDuplicates,
            AtLeastTwoRecords = analysis.AtLeastTwoRecords,
            AllHaveAOrAaaa = analysis.AllHaveAOrAaaa,
            PointsToCname = analysis.PointsToCname,
            HasDiverseLocations = analysis.HasDiverseLocations,
            AsnDistinctCount = analysis.AsnDistinctCount,
            ParentNsRecords = analysis.ParentNsRecords,
            DelegationMatches = analysis.DelegationMatches,
            GlueRecordsComplete = analysis.GlueRecordsComplete,
            GlueRecordsConsistent = analysis.GlueRecordsConsistent,
            RootServerResponses = analysis.RootServerResponses,
            RecursionEnabled = analysis.RecursionEnabled,
            Assessments = analysis.Assessments,
            Status = analysis.DnsQueryFailed ? "Incomplete" : status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = !analysis.NsLookupComplete ? "NS discovery incomplete; record presence unknown"
                : !analysis.DelegationAnalysisComplete ? $"{analysis.NsRecords.Count} NS; parent delegation/glue unverified; ASNs {analysis.AsnDistinctCount}"
                : $"{analysis.NsRecords.Count} NS; glue {(analysis.GlueRecordsComplete ? "complete" : "incomplete")}/{(!analysis.GlueRecordsComplete ? "unverified" : analysis.GlueRecordsConsistent ? "consistent" : "mixed")}; ASNs {analysis.AsnDistinctCount}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing NS (authoritative name servers) analysis.
/// </summary>
public class NsInfo
{
    /// <summary>Type of health check.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Logical analysis area.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Subject domain.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>NS records at the child zone.</summary>
    public IReadOnlyList<string> NsRecords { get; set; } = System.Array.Empty<string>();
    /// <summary>True when at least one NS record exists.</summary>
    public bool NsRecordExists { get; set; }
    /// <summary>True when child NS discovery completed with conclusive DNS evidence.</summary>
    public bool NsLookupComplete { get; set; }
    /// <summary>Record presence is unknown when discovery could not complete.</summary>
    public string RecordPresence => NsRecordExists ? "Yes" : NsLookupComplete ? "No" : "Unknown";
    /// <summary>True when DNS query failures leave any analyzed NS evidence incomplete.</summary>
    public bool DnsQueryFailed { get; set; }
    /// <summary>DNS failures retained separately from confirmed policy problems.</summary>
    public IReadOnlyList<string> DnsQueryErrors { get; set; } = System.Array.Empty<string>();
    /// <summary>True when the parent delegation and applicable glue checks completed.</summary>
    public bool DelegationAnalysisComplete { get; set; }
    /// <summary>True when duplicate NS names are present.</summary>
    public bool HasDuplicates { get; set; }
    /// <summary>True when two or more NS records exist.</summary>
    public bool AtLeastTwoRecords { get; set; }
    /// <summary>True when every NS name resolves to A/AAAA.</summary>
    public bool AllHaveAOrAaaa { get; set; }
    /// <summary>True when any NS name points to a CNAME.</summary>
    public bool PointsToCname { get; set; }
    /// <summary>True when NS servers are geographically diverse.</summary>
    public bool HasDiverseLocations { get; set; }
    /// <summary>Number of distinct ASNs among NS IP addresses.</summary>
    public int AsnDistinctCount { get; set; }
    /// <summary>NS records at the parent zone (delegation).</summary>
    public IReadOnlyList<string> ParentNsRecords { get; set; } = System.Array.Empty<string>();
    /// <summary>True when parent and child NS sets match.</summary>
    public bool DelegationMatches { get; set; }
    /// <summary>True when glue records are present for in-bailiwick NS.</summary>
    public bool GlueRecordsComplete { get; set; }
    /// <summary>True when applicable glue in the observed parent response matches child A/AAAA records.</summary>
    public bool GlueRecordsConsistent { get; set; }
    /// <summary>DNS response status from root/parent servers.</summary>
    public IReadOnlyDictionary<string, bool> RootServerResponses { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    /// <summary>Recursion availability results per server.</summary>
    public IReadOnlyDictionary<string, bool> RecursionEnabled { get; set; } = new System.Collections.Generic.Dictionary<string, bool>();
    /// <summary>Assessment list.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Overall status (OK/Warning/Error).</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Short summary text for executive reports.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Actionable recommendations.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Positive posture notes.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Reference links.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Underlying analysis.</summary>
    public NSAnalysis Raw { get; set; } = new NSAnalysis();
}
