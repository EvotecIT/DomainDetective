using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the providers checked value.</summary>
    public int ProvidersChecked { get; set; }
    /// <summary>Gets or sets the hosts checked value.</summary>
    public int HostsChecked { get; set; }
    /// <summary>Gets or sets the hosts listed value.</summary>
    public int HostsListed { get; set; }
    /// <summary>Gets or sets the providers with listings value.</summary>
    public int ProvidersWithListings { get; set; }
    /// <summary>Gets or sets the listed records value.</summary>
    public IReadOnlyList<DNSBLRecord> ListedRecords { get; set; } = System.Array.Empty<DNSBLRecord>();
    /// <summary>Gets or sets the host summaries value.</summary>
    public IReadOnlyList<DnsblHostSummary> HostSummaries { get; set; } = System.Array.Empty<DnsblHostSummary>();
    /// <summary>Gets or sets the targets value.</summary>
    public IReadOnlyList<DnsblTargetInfo> Targets { get; set; } = System.Array.Empty<DnsblTargetInfo>();
    /// <summary>Gets or sets the listings value.</summary>
    public IReadOnlyList<DnsblListingInfo> Listings { get; set; } = System.Array.Empty<DnsblListingInfo>();
    /// <summary>Gets or sets the pathways value.</summary>
    public IReadOnlyList<DnsblPathwayInfo> Pathways { get; set; } = System.Array.Empty<DnsblPathwayInfo>();
    /// <summary>Gets or sets the provider summaries value.</summary>
    public IReadOnlyList<DnsblProviderSummary> ProviderSummaries { get; set; } = System.Array.Empty<DnsblProviderSummary>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.DnsblNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.DnsblNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public DNSBLAnalysis Raw { get; set; } = new DNSBLAnalysis();
}

/// <summary>
/// Brief per-host DNSBL summary used in DNSBL reports.
/// </summary>
public class DnsblHostSummary
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the total value.</summary>
    public int Total { get; set; }
    /// <summary>Gets or sets the listed value.</summary>
    public int Listed { get; set; }
    /// <summary>Gets or sets the blacklists value.</summary>
    public IReadOnlyList<string> Blacklists { get; set; } = System.Array.Empty<string>();
}

/// <summary>Provides dnsbl target info functionality.</summary>
public class DnsblTargetInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Gets or sets the primary pathway value.</summary>
    public string PrimaryPathway { get; set; } = string.Empty;
    /// <summary>Gets or sets the pathways value.</summary>
    public IReadOnlyList<string> Pathways { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the query kinds value.</summary>
    public IReadOnlyList<string> QueryKinds { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the source hosts value.</summary>
    public IReadOnlyList<string> SourceHosts { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the providers checked value.</summary>
    public int ProvidersChecked { get; set; }
    /// <summary>Gets or sets the providers listed value.</summary>
    public int ProvidersListed { get; set; }
    /// <summary>Gets or sets the listed providers value.</summary>
    public IReadOnlyList<string> ListedProviders { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the example query value.</summary>
    public string ExampleQuery { get; set; } = string.Empty;
}

/// <summary>Provides dnsbl listing info functionality.</summary>
public class DnsblListingInfo
{
    /// <summary>Gets or sets the target value.</summary>
    public string Target { get; set; } = string.Empty;
    /// <summary>Gets or sets the provider value.</summary>
    public string Provider { get; set; } = string.Empty;
    /// <summary>Gets or sets the pathway value.</summary>
    public string Pathway { get; set; } = string.Empty;
    /// <summary>Gets or sets the query kind value.</summary>
    public string QueryKind { get; set; } = string.Empty;
    /// <summary>Gets or sets the source host value.</summary>
    public string SourceHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the query value.</summary>
    public string Query { get; set; } = string.Empty;
    /// <summary>Gets or sets the fully qualified query value.</summary>
    public string FullyQualifiedQuery { get; set; } = string.Empty;
    /// <summary>Gets or sets the answer value.</summary>
    public string Answer { get; set; } = string.Empty;
    /// <summary>Gets or sets the meaning value.</summary>
    public string Meaning { get; set; } = string.Empty;
}

/// <summary>Provides dnsbl pathway info functionality.</summary>
public class DnsblPathwayInfo
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the label value.</summary>
    public string Label { get; set; } = string.Empty;
    /// <summary>Gets or sets the targets checked value.</summary>
    public int TargetsChecked { get; set; }
    /// <summary>Gets or sets the listed targets value.</summary>
    public int ListedTargets { get; set; }
    /// <summary>Gets or sets the providers checked value.</summary>
    public int ProvidersChecked { get; set; }
    /// <summary>Gets or sets the providers with listings value.</summary>
    public int ProvidersWithListings { get; set; }
    /// <summary>Gets or sets the query kinds value.</summary>
    public IReadOnlyList<string> QueryKinds { get; set; } = System.Array.Empty<string>();
}

/// <summary>Provides dnsbl provider summary functionality.</summary>
public class DnsblProviderSummary
{
    /// <summary>Gets or sets the provider value.</summary>
    public string Provider { get; set; } = string.Empty;
    /// <summary>Gets or sets the query count value.</summary>
    public int QueryCount { get; set; }
    /// <summary>Gets or sets the listed count value.</summary>
    public int ListedCount { get; set; }
    /// <summary>Gets or sets the listed targets value.</summary>
    public IReadOnlyList<string> ListedTargets { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the meanings value.</summary>
    public IReadOnlyList<string> Meanings { get; set; } = System.Array.Empty<string>();
}
