using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static EdnsSupportSummary Convert(EdnsSupportAnalysis analysis)
    {
        var total = analysis.ServerSupport?.Count ?? 0;
        var supported = analysis.ServerSupport?.Values.Count(v => v.Supported) ?? 0;
        var notSupported = total - supported;
        var entries = analysis.ServerSupport?.Select(kv => new EdnsServerInfo
        {
            Key = kv.Key,
            Supported = kv.Value.Supported,
            UdpPayloadSize = kv.Value.UdpPayloadSize,
            DoBit = kv.Value.DoBit,
            TruncatedUdp = kv.Value.TruncatedUdp
        }).ToList() ?? new List<EdnsServerInfo>();
        var largeUdp = entries.Count(e => e.UdpPayloadSize > 1232);
        var truncated = entries.Count(e => e.TruncatedUdp);

        // Normalize assessments → recommendations/positives and counts
        var assessments = (analysis as IHasAssessments)?.Assessments ?? new List<Assessment>();
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        return new EdnsSupportSummary
        {
            Check = HealthCheckType.EDNSSUPPORT,
            Area = AreaForKind(HealthCheckType.EDNSSUPPORT),
            Subject = analysis.Subject,
            TotalChecked = total,
            SupportedCount = supported,
            NotSupportedCount = notSupported,
            Servers = entries,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{supported}/{total} EDNS; >1232: {largeUdp}; TCP fb: {truncated}; no-edns: {notSupported}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.RfcReferences, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides edns support summary functionality.</summary>
public class EdnsSupportSummary
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the supported count value.</summary>
    public int SupportedCount { get; set; }
    /// <summary>Gets or sets the not supported count value.</summary>
    public int NotSupportedCount { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyList<EdnsServerInfo> Servers { get; set; } = null!;
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public EdnsSupportAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides edns server info functionality.</summary>
public class EdnsServerInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Gets or sets the supported value.</summary>
    public bool Supported { get; set; }
    /// <summary>Gets or sets the udp payload size value.</summary>
    public int UdpPayloadSize { get; set; }
    /// <summary>Gets or sets the do bit value.</summary>
    public bool DoBit { get; set; }
    /// <summary>Gets or sets the truncated udp value.</summary>
    public bool TruncatedUdp { get; set; }
}
