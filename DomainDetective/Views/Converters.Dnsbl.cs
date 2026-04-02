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
        var narrative = DomainDetective.Narratives.DnsblNarrative.Build(analysis, analysis.Assessments);
        var hostSummaries = analysis.Results?.Select(kv => new DnsblHostSummary
        {
            Key = kv.Key,
            Total = kv.Value.Total,
            Listed = kv.Value.Listed,
            Blacklists = kv.Value.ListedBlacklist
        }).ToList() ?? new List<DnsblHostSummary>();

        var allResults = analysis.AllResults?.ToList() ?? new List<DNSBLRecord>();
        var listedRecords = allResults.Where(r => r.IsBlackListed).ToList();
        var targets = BuildTargets(allResults, analysis.Results);
        var listings = BuildListings(listedRecords);
        var pathways = BuildPathways(allResults);
        var providerSummaries = BuildProviders(allResults);
        var listedProviders = listings
            .Select(static listing => listing.Provider)
            .Distinct(System.StringComparer.OrdinalIgnoreCase)
            .Count();

        return new DnsblInfo
        {
            Check = HealthCheckType.DNSBL,
            Area = AreaForKind(HealthCheckType.DNSBL),
            // Subject is domain-scoped when analysis was invoked with a domain; null for multi-input/IP-only runs
            Subject = analysis.Subject,
            ProvidersChecked = analysis.GetDNSBL().Count,
            HostsChecked = analysis.RecordChecked,
            HostsListed = analysis.Blacklisted,
            ListedRecords = listedRecords,
            HostSummaries = hostSummaries,
            Targets = targets,
            Listings = listings,
            Pathways = pathways,
            ProvidersWithListings = listedProviders,
            ProviderSummaries = providerSummaries,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"listed hosts {analysis.Blacklisted}/{analysis.RecordChecked}",
            Recommendations = recs,
            Positives = positives,
            References = (narrative.References?.Count ?? 0) > 0
                ? narrative.References!.ToList()
                : new [] { "https://datatracker.ietf.org/doc/html/rfc5782" },
            Narrative = narrative,
            Highlights = narrative.Highlights?.ToList() ?? new List<string>(),
            Details = narrative.Details?.ToList() ?? new List<string>(),
            Raw = analysis
        };
    }

    private static IReadOnlyList<DnsblTargetInfo> BuildTargets(
        IReadOnlyList<DNSBLRecord> records,
        IReadOnlyDictionary<string, DNSQueryResult>? results)
    {
        if (records.Count == 0 && (results == null || results.Count == 0))
        {
            return System.Array.Empty<DnsblTargetInfo>();
        }

        return records
            .GroupBy(GetTargetKey, System.StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var first = group.First();
                var providersChecked = results != null && results.TryGetValue(group.Key, out var summary)
                    ? summary.Total
                    : group.Select(static item => item.BlackList).Distinct(System.StringComparer.OrdinalIgnoreCase).Count();
                var listedProviders = group
                    .Where(static item => item.IsBlackListed)
                    .Select(static item => item.BlackList)
                    .Distinct(System.StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var sourceHosts = group
                    .Select(static item => item.SourceHost)
                    .Where(static item => !string.IsNullOrWhiteSpace(item))
                    .Select(static item => item!)
                    .Distinct(System.StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var pathways = group
                    .Select(GetPathwayKey)
                    .Distinct(System.StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                var queryKinds = group
                    .Select(static item => FormatQueryKind(item.QueryKind))
                    .Distinct(System.StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                return new DnsblTargetInfo
                {
                    Key = group.Key,
                    Label = GetTargetLabel(first),
                    PrimaryPathway = GetPathwayLabel(first),
                    Pathways = pathways,
                    QueryKinds = queryKinds,
                    SourceHosts = sourceHosts,
                    ProvidersChecked = providersChecked,
                    ProvidersListed = listedProviders.Length,
                    ListedProviders = listedProviders,
                    ExampleQuery = group
                        .Select(static item => item.Query)
                        .FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item)) ?? string.Empty
                };
            })
            .OrderByDescending(static item => item.ProvidersListed)
            .ThenBy(static item => item.Label, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<DnsblListingInfo> BuildListings(IReadOnlyList<DNSBLRecord> listedRecords)
    {
        if (listedRecords.Count == 0)
        {
            return System.Array.Empty<DnsblListingInfo>();
        }

        return listedRecords
            .Select(static record => new DnsblListingInfo
            {
                Target = GetTargetLabel(record),
                Provider = record.BlackList,
                Pathway = GetPathwayLabel(record),
                QueryKind = FormatQueryKind(record.QueryKind),
                SourceHost = record.SourceHost ?? string.Empty,
                Query = record.Query ?? string.Empty,
                FullyQualifiedQuery = record.FQDN ?? string.Empty,
                Answer = record.Answer ?? string.Empty,
                Meaning = string.IsNullOrWhiteSpace(record.ReplyMeaning) ? "Listed" : record.ReplyMeaning
            })
            .OrderBy(static item => item.Target, System.StringComparer.OrdinalIgnoreCase)
            .ThenBy(static item => item.Provider, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<DnsblPathwayInfo> BuildPathways(IReadOnlyList<DNSBLRecord> records)
    {
        if (records.Count == 0)
        {
            return System.Array.Empty<DnsblPathwayInfo>();
        }

        return records
            .GroupBy(GetPathwayKey, System.StringComparer.OrdinalIgnoreCase)
            .Select(group => new DnsblPathwayInfo
            {
                Key = group.Key,
                Label = GetPathwayLabel(group.First()),
                TargetsChecked = group.Select(GetTargetKey).Distinct(System.StringComparer.OrdinalIgnoreCase).Count(),
                ListedTargets = group.Where(static item => item.IsBlackListed).Select(GetTargetKey).Distinct(System.StringComparer.OrdinalIgnoreCase).Count(),
                ProvidersChecked = group.Select(static item => item.BlackList).Distinct(System.StringComparer.OrdinalIgnoreCase).Count(),
                ProvidersWithListings = group.Where(static item => item.IsBlackListed).Select(static item => item.BlackList).Distinct(System.StringComparer.OrdinalIgnoreCase).Count(),
                QueryKinds = group.Select(static item => FormatQueryKind(item.QueryKind)).Distinct(System.StringComparer.OrdinalIgnoreCase).OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase).ToArray()
            })
            .OrderByDescending(static item => item.ListedTargets)
            .ThenByDescending(static item => item.TargetsChecked)
            .ThenBy(static item => item.Label, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IReadOnlyList<DnsblProviderSummary> BuildProviders(IReadOnlyList<DNSBLRecord> records)
    {
        if (records.Count == 0)
        {
            return System.Array.Empty<DnsblProviderSummary>();
        }

        return records
            .GroupBy(static item => item.BlackList, System.StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var listedTargets = group.Where(static item => item.IsBlackListed).Select(GetTargetKey).Distinct(System.StringComparer.OrdinalIgnoreCase).OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase).ToArray();
                return new DnsblProviderSummary
                {
                    Provider = group.Key,
                    QueryCount = group.Count(),
                    ListedTargets = listedTargets,
                    ListedCount = listedTargets.Length,
                    Meanings = group.Where(static item => item.IsBlackListed).Select(static item => item.ReplyMeaning).Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(System.StringComparer.OrdinalIgnoreCase).OrderBy(static item => item, System.StringComparer.OrdinalIgnoreCase).ToArray()
                };
            })
            .OrderByDescending(static item => item.ListedCount)
            .ThenBy(static item => item.Provider, System.StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string GetTargetKey(DNSBLRecord record)
    {
        if (!string.IsNullOrWhiteSpace(record.IpAddress))
        {
            return record.IpAddress!;
        }

        if (!string.IsNullOrWhiteSpace(record.SourceHost))
        {
            return record.SourceHost!;
        }

        return record.Query ?? string.Empty;
    }

    private static string GetTargetLabel(DNSBLRecord record)
    {
        if (!string.IsNullOrWhiteSpace(record.IpAddress) && !string.IsNullOrWhiteSpace(record.SourceHost))
        {
            return $"{record.SourceHost} ({record.IpAddress})";
        }

        if (!string.IsNullOrWhiteSpace(record.IpAddress))
        {
            return record.IpAddress!;
        }

        if (!string.IsNullOrWhiteSpace(record.SourceHost))
        {
            return record.SourceHost!;
        }

        return record.Query ?? "Target";
    }

    private static string GetPathwayKey(DNSBLRecord record)
    {
        return record.IpSource?.ToString() ?? record.QueryKind.ToString();
    }

    private static string GetPathwayLabel(DNSBLRecord record)
    {
        return record.IpSource switch
        {
            DnsblIpSource.Domain => "Domain blocklists",
            DnsblIpSource.MxA => "MX host IPv4",
            DnsblIpSource.MxAAAA => "MX host IPv6",
            DnsblIpSource.ApexA => "Apex IPv4 fallback",
            DnsblIpSource.ApexAAAA => "Apex IPv6 fallback",
            DnsblIpSource.UserProvided => "Direct IP input",
            _ => record.QueryKind switch
            {
                DnsblQueryKind.Domain => "Domain blocklists",
                DnsblQueryKind.IpAddressV4 => "IPv4 address checks",
                DnsblQueryKind.IpAddressV6 => "IPv6 address checks",
                _ => "DNSBL checks"
            }
        };
    }

    private static string FormatQueryKind(DnsblQueryKind queryKind)
    {
        return queryKind switch
        {
            DnsblQueryKind.Domain => "Domain",
            DnsblQueryKind.IpAddressV4 => "IPv4",
            DnsblQueryKind.IpAddressV6 => "IPv6",
            DnsblQueryKind.IpAddress => "IP",
            _ => queryKind.ToString()
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
    public string? Subject { get; set; }
    public int ProvidersChecked { get; set; }
    public int HostsChecked { get; set; }
    public int HostsListed { get; set; }
    public int ProvidersWithListings { get; set; }
    public IReadOnlyList<DNSBLRecord> ListedRecords { get; set; } = System.Array.Empty<DNSBLRecord>();
    public IReadOnlyList<DnsblHostSummary> HostSummaries { get; set; } = System.Array.Empty<DnsblHostSummary>();
    public IReadOnlyList<DnsblTargetInfo> Targets { get; set; } = System.Array.Empty<DnsblTargetInfo>();
    public IReadOnlyList<DnsblListingInfo> Listings { get; set; } = System.Array.Empty<DnsblListingInfo>();
    public IReadOnlyList<DnsblPathwayInfo> Pathways { get; set; } = System.Array.Empty<DnsblPathwayInfo>();
    public IReadOnlyList<DnsblProviderSummary> ProviderSummaries { get; set; } = System.Array.Empty<DnsblProviderSummary>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public DomainDetective.Narratives.DnsblNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DnsblNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
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

public class DnsblTargetInfo
{
    public string Key { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string PrimaryPathway { get; set; } = string.Empty;
    public IReadOnlyList<string> Pathways { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> QueryKinds { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> SourceHosts { get; set; } = System.Array.Empty<string>();
    public int ProvidersChecked { get; set; }
    public int ProvidersListed { get; set; }
    public IReadOnlyList<string> ListedProviders { get; set; } = System.Array.Empty<string>();
    public string ExampleQuery { get; set; } = string.Empty;
}

public class DnsblListingInfo
{
    public string Target { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public string Pathway { get; set; } = string.Empty;
    public string QueryKind { get; set; } = string.Empty;
    public string SourceHost { get; set; } = string.Empty;
    public string Query { get; set; } = string.Empty;
    public string FullyQualifiedQuery { get; set; } = string.Empty;
    public string Answer { get; set; } = string.Empty;
    public string Meaning { get; set; } = string.Empty;
}

public class DnsblPathwayInfo
{
    public string Key { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public int TargetsChecked { get; set; }
    public int ListedTargets { get; set; }
    public int ProvidersChecked { get; set; }
    public int ProvidersWithListings { get; set; }
    public IReadOnlyList<string> QueryKinds { get; set; } = System.Array.Empty<string>();
}

public class DnsblProviderSummary
{
    public string Provider { get; set; } = string.Empty;
    public int QueryCount { get; set; }
    public int ListedCount { get; set; }
    public IReadOnlyList<string> ListedTargets { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Meanings { get; set; } = System.Array.Empty<string>();
}
