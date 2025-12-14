using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsblInfo Convert(DNSBLAnalysis analysis)
    {
        // DNSBLAnalysis already emits assessments for listed/timeouts/failures.
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var hostSummaries = analysis.Results?.Select(kv => new DnsblHostSummary
        {
            Key = kv.Key,
            Total = kv.Value.Total,
            Listed = kv.Value.Listed,
            Blacklists = kv.Value.ListedBlacklist
        }).ToList() ?? new List<DnsblHostSummary>();

        var listedRecords = analysis.AllResults?.Where(r => r.IsBlackListed).ToList() ?? new List<DNSBLRecord>();
        // Subject is domain-scoped when analysis was invoked with a domain; null for multi-input/IP-only runs
        string subject = analysis.Subject ?? string.Empty;

        return new DnsblInfo
        {
            Check = HealthCheckType.DNSBL,
            Area = AreaForKind(HealthCheckType.DNSBL),
            Subject = subject,
            ProvidersChecked = analysis.GetDNSBL().Count,
            HostsChecked = analysis.RecordChecked,
            HostsListed = analysis.Blacklisted,
            ListedRecords = listedRecords,
            HostSummaries = hostSummaries,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"listed hosts {analysis.Blacklisted}/{analysis.RecordChecked}",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://datatracker.ietf.org/doc/html/rfc5782" },
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing DNSBL blacklist checks.
/// </summary>
public class DnsblInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;
    public int ProvidersChecked { get; set; }
    public int HostsChecked { get; set; }
    public int HostsListed { get; set; }
    public IReadOnlyList<DNSBLRecord> ListedRecords { get; set; } = System.Array.Empty<DNSBLRecord>();
    public IReadOnlyList<DnsblHostSummary> HostSummaries { get; set; } = System.Array.Empty<DnsblHostSummary>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DNSBLAnalysis Raw { get; set; } = new DNSBLAnalysis();
}

/// <summary>
/// Brief per-host DNSBL summary used in DNSBL reports.
/// </summary>
public class DnsblHostSummary
{
    public string Key { get; set; } = string.Empty;
    public int Total { get; set; }
    public int Listed { get; set; }
    public IReadOnlyList<string> Blacklists { get; set; } = System.Array.Empty<string>();
}
