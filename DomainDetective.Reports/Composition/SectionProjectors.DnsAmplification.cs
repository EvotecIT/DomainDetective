using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective.Reports;

public static partial class SectionProjectors
{
    // DNS: Amplification posture (recursion + EDNS + response size probes)
    public sealed class DnsAmplificationSection
    {
        public sealed class ServerRow
        {
            public string Key { get; set; } = string.Empty;
            public string NameServerHost { get; set; } = string.Empty;
            public string ServerIp { get; set; } = string.Empty;
            public bool OpenRecursion { get; set; }
            public bool EdnsSupported { get; set; }
            public int? EdnsUdpPayloadSize { get; set; }
            public bool EdnsTruncatedUdp { get; set; }
            public string WorstProbeType { get; set; } = "-";
            public string WorstProbeName { get; set; } = "-";
            public int WorstProbeResponseBytes { get; set; }
            public bool WorstProbeTruncated { get; set; }
            public double WorstProbeAmplificationFactor { get; set; }
        }

        public string Status { get; set; } = "-";
        public int TotalChecked { get; set; }
        public int OpenRecursionCount { get; set; }
        public int LargeUdpResponseCount { get; set; }
        public int WarningCount { get; set; }
        public int ErrorCount { get; set; }
        public List<(string Key, string Value)> Summary { get; } = new();
        public List<ServerRow> Servers { get; } = new();
        public List<SimpleFinding> Findings { get; } = new();
        public List<string> Positives { get; } = new();
        public List<string> References { get; } = new();
    }

    public static DnsAmplificationSection? BuildDnsAmplification(DomainDetective.Views.DnsAmplificationSummary summary)
    {
        if (summary == null)
        {
            return null;
        }

        var servers = summary.Servers ?? Array.Empty<DomainDetective.Views.DnsAmplificationServerInfo>();
        var maxBytes = servers.Count == 0 ? 0 : servers.Max(s => s.WorstProbeResponseBytes);
        var maxAmp = servers.Count == 0 ? 0 : servers.Max(s => s.WorstProbeAmplificationFactor);

        var sec = new DnsAmplificationSection
        {
            Status = summary.Status ?? "-",
            TotalChecked = summary.TotalChecked,
            OpenRecursionCount = summary.OpenRecursionCount,
            LargeUdpResponseCount = summary.LargeUdpResponseCount,
            WarningCount = summary.WarningCount,
            ErrorCount = summary.ErrorCount
        };

        sec.Summary.Add(("Status", sec.Status));
        sec.Summary.Add(("Servers checked", sec.TotalChecked.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Open recursion", sec.OpenRecursionCount.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Large UDP responses", sec.LargeUdpResponseCount.ToString(CultureInfo.InvariantCulture)));
        sec.Summary.Add(("Max response", $"{maxBytes.ToString(CultureInfo.InvariantCulture)} B"));
        sec.Summary.Add(("Max amplification", $"{maxAmp.ToString("0.0", CultureInfo.InvariantCulture)}x"));

        foreach (var s in servers.OrderByDescending(x => x.WorstProbeResponseBytes).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
        {
            var nameServerHost = s.NameServerHost;
            var serverIp = s.ServerIp;
            var worstProbeName = s.WorstProbeName;

            sec.Servers.Add(new DnsAmplificationSection.ServerRow
            {
                Key = s.Key ?? string.Empty,
                NameServerHost = string.IsNullOrWhiteSpace(nameServerHost) ? "-" : nameServerHost,
                ServerIp = string.IsNullOrWhiteSpace(serverIp) ? "-" : serverIp,
                OpenRecursion = s.OpenRecursion,
                EdnsSupported = s.EdnsSupported,
                EdnsUdpPayloadSize = s.EdnsUdpPayloadSize,
                EdnsTruncatedUdp = s.EdnsTruncatedUdp,
                WorstProbeType = s.WorstProbeType?.ToString() ?? "-",
                WorstProbeName = string.IsNullOrWhiteSpace(worstProbeName) ? "-" : (worstProbeName ?? "-"),
                WorstProbeResponseBytes = s.WorstProbeResponseBytes,
                WorstProbeTruncated = s.WorstProbeTruncated,
                WorstProbeAmplificationFactor = s.WorstProbeAmplificationFactor
            });
        }

        foreach (var a in summary.Assessments ?? Array.Empty<DomainDetective.Assessment>())
        {
            if (a == null || a.Severity == DomainDetective.AssessmentSeverity.Info)
            {
                continue;
            }
            sec.Findings.Add(new SimpleFinding(a.Severity.ToString(), a.Code ?? string.Empty, a.Target ?? string.Empty, a.Message ?? string.Empty));
        }

        foreach (var p in summary.Positives ?? Array.Empty<DomainDetective.RecommendationAdvice>())
        {
            var t = p?.Title ?? p?.Code;
            if (!string.IsNullOrWhiteSpace(t))
            {
                sec.Positives.Add(t!);
            }
        }

        foreach (var r in summary.References ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(r))
            {
                sec.References.Add(r);
            }
        }

        return sec;
    }
}
