using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public sealed class DnsAmplificationSummary
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public int TotalChecked { get; set; }
    public int OpenRecursionCount { get; set; }
    public int LargeUdpResponseCount { get; set; }
    public IReadOnlyList<DnsAmplificationServerInfo> Servers { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsAmplificationAnalysis Raw { get; set; } = null!;
}

public sealed class DnsAmplificationServerInfo
{
    public string Key { get; set; } = null!;
    public string NameServerHost { get; set; } = string.Empty;
    public string ServerIp { get; set; } = string.Empty;
    public bool OpenRecursion { get; set; }
    public bool EdnsSupported { get; set; }
    public int? EdnsUdpPayloadSize { get; set; }
    public bool EdnsTruncatedUdp { get; set; }
    public DnsClientX.DnsRecordType? WorstProbeType { get; set; }
    public string? WorstProbeName { get; set; }
    public int WorstProbeResponseBytes { get; set; }
    public bool WorstProbeTruncated { get; set; }
    public double WorstProbeAmplificationFactor { get; set; }
}

