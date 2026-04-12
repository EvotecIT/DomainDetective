using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static DnsAmplificationSummary Convert(DnsAmplificationAnalysis analysis)
    {
        var total = analysis.ServerResults?.Count ?? 0;
        var servers = analysis.ServerResults?.Select(kv =>
        {
            var worst = kv.Value.Probes?.OrderByDescending(p => p.ResponseBytes).FirstOrDefault();
            return new DnsAmplificationServerInfo
            {
                Key = kv.Key,
                NameServerHost = kv.Value.NameServerHost,
                ServerIp = kv.Value.ServerIp,
                OpenRecursion = kv.Value.OpenRecursion,
                EdnsSupported = kv.Value.EdnsSupported,
                EdnsUdpPayloadSize = kv.Value.EdnsUdpPayloadSize,
                EdnsTruncatedUdp = kv.Value.EdnsTruncatedUdp,
                WorstProbeType = worst?.QueryType,
                WorstProbeName = worst?.QueryName,
                WorstProbeResponseBytes = worst?.ResponseBytes ?? 0,
                WorstProbeTruncated = worst?.Truncated ?? false,
                WorstProbeAmplificationFactor = worst?.AmplificationFactor ?? 0
            };
        }).ToList() ?? new List<DnsAmplificationServerInfo>();

        var open = servers.Count(s => s.OpenRecursion);
        var largeUdp = servers.Count(s => s.WorstProbeResponseBytes > analysis.LargeUdpResponseThreshold && !s.WorstProbeTruncated);
        var maxBytes = servers.Count == 0 ? 0 : servers.Max(s => s.WorstProbeResponseBytes);
        var maxAmp = servers.Count == 0 ? 0 : servers.Max(s => s.WorstProbeAmplificationFactor);

        var assessments = analysis.Assessments ?? new List<Assessment>();
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        Summarize(assessments, out var warnCount, out var errCount, out var status);

        return new DnsAmplificationSummary
        {
            Check = HealthCheckType.DNSAMPLIFICATION,
            Area = AreaForKind(HealthCheckType.DNSAMPLIFICATION),
            Subject = analysis.Subject,
            TotalChecked = total,
            OpenRecursionCount = open,
            LargeUdpResponseCount = largeUdp,
            Servers = servers,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = string.Format(CultureInfo.InvariantCulture, "servers {0}; open-rec {1}; large-udp {2}; max {3}B; max {4:F1}x", total, open, largeUdp, maxBytes, maxAmp),
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides dns amplification summary functionality.</summary>
public sealed class DnsAmplificationSummary
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the total checked value.</summary>
    public int TotalChecked { get; set; }
    /// <summary>Gets or sets the open recursion count value.</summary>
    public int OpenRecursionCount { get; set; }
    /// <summary>Gets or sets the large udp response count value.</summary>
    public int LargeUdpResponseCount { get; set; }
    /// <summary>Gets or sets the servers value.</summary>
    public IReadOnlyList<DnsAmplificationServerInfo> Servers { get; set; } = null!;
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
    public DnsAmplificationAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides dns amplification server info functionality.</summary>
public sealed class DnsAmplificationServerInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = null!;
    /// <summary>Gets or sets the name server host value.</summary>
    public string NameServerHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the server ip value.</summary>
    public string ServerIp { get; set; } = string.Empty;
    /// <summary>Gets or sets the open recursion value.</summary>
    public bool OpenRecursion { get; set; }
    /// <summary>Gets or sets the edns supported value.</summary>
    public bool EdnsSupported { get; set; }
    /// <summary>Gets or sets the edns udp payload size value.</summary>
    public int? EdnsUdpPayloadSize { get; set; }
    /// <summary>Gets or sets the edns truncated udp value.</summary>
    public bool EdnsTruncatedUdp { get; set; }
    /// <summary>Gets or sets the worst probe type value.</summary>
    public DnsClientX.DnsRecordType? WorstProbeType { get; set; }
    /// <summary>Gets or sets the worst probe name value.</summary>
    public string? WorstProbeName { get; set; }
    /// <summary>Gets or sets the worst probe response bytes value.</summary>
    public int WorstProbeResponseBytes { get; set; }
    /// <summary>Gets or sets the worst probe truncated value.</summary>
    public bool WorstProbeTruncated { get; set; }
    /// <summary>Gets or sets the worst probe amplification factor value.</summary>
    public double WorstProbeAmplificationFactor { get; set; }
}

