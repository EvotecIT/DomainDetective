using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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
        return new EdnsSupportSummary
        {
            Check = HealthCheckType.EDNSSUPPORT,
            Area = AreaForKind(HealthCheckType.EDNSSUPPORT),
            Subject = analysis.Subject,
            TotalChecked = total,
            SupportedCount = supported,
            NotSupportedCount = notSupported,
            Servers = entries,
            Assessments = (analysis as IHasAssessments)?.Assessments ?? new List<Assessment>(),
            Status = notSupported > 0 ? "Warning" : "OK",
            WarningCount = notSupported,
            ErrorCount = 0,
            Summary = $"{supported}/{total} EDNS; >1232: {largeUdp}; TCP fb: {truncated}; no-edns: {notSupported}",
            Recommendations = (analysis as IHasAssessments) != null ? RecommendationEngine.FromProblems(((IHasAssessments)analysis).Assessments) : new List<RecommendationAdvice>(),
            References = new [] { "https://www.rfc-editor.org/rfc/rfc6891" },
            Raw = analysis
        };
    }
}

public class EdnsSupportSummary
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public int TotalChecked { get; set; }
    public int SupportedCount { get; set; }
    public int NotSupportedCount { get; set; }
    public IReadOnlyList<EdnsServerInfo> Servers { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public EdnsSupportAnalysis Raw { get; set; }
}

public class EdnsServerInfo
{
    public string Key { get; set; }
    public bool Supported { get; set; }
    public int UdpPayloadSize { get; set; }
    public bool DoBit { get; set; }
    public bool TruncatedUdp { get; set; }
}
