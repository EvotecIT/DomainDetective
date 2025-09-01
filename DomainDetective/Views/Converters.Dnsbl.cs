using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsblInfo Convert(DNSBLAnalysis analysis)
    {
        // DNSBLAnalysis already emits assessments for listed/timeouts/failures.
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var hostSummaries = analysis.Results?.Select(kv => new DnsblHostSummary
        {
            Key = kv.Key,
            Total = kv.Value.Total,
            Listed = kv.Value.Listed,
            Blacklists = kv.Value.ListedBlacklist
        }).ToList() ?? new List<DnsblHostSummary>();

        var listedRecords = analysis.AllResults?.Where(r => r.IsBlackListed).ToList() ?? new List<DNSBLRecord>();

        // Pick a subject: prefer a domain-like key; else first key
        string subject = null;
        try {
            var keys = analysis.Results?.Keys?.ToList();
            if (keys != null && keys.Count > 0) {
                string pick = null;
                foreach (var k in keys) {
                    if (!System.Net.IPAddress.TryParse(k, out _)) { pick = k; break; }
                }
                subject = pick ?? keys[0];
            }
        } catch { }

        return new DnsblInfo
        {
            Check = "DNSBL",
            Area = AreaFor("DNSBL"),
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
            References = new [] { "https://datatracker.ietf.org/doc/html/rfc5782" },
            Raw = analysis
        };
    }
}

public class DnsblInfo
{
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public int ProvidersChecked { get; set; }
    public int HostsChecked { get; set; }
    public int HostsListed { get; set; }
    public IReadOnlyList<DNSBLRecord> ListedRecords { get; set; }
    public IReadOnlyList<DnsblHostSummary> HostSummaries { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public DNSBLAnalysis Raw { get; set; }
}

public class DnsblHostSummary
{
    public string Key { get; set; }
    public int Total { get; set; }
    public int Listed { get; set; }
    public IReadOnlyList<string> Blacklists { get; set; }
}
