using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    /// Compares DNS answers across multiple public resolvers (global visibility).
    /// </summary>
    public async Task VerifyDnsPropagationAsync(string domainName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domainName))
        {
            throw new ArgumentNullException(nameof(domainName));
        }

        domainName = NormalizeDomain(domainName);
        UpdateIsPublicSuffix(domainName);
        if (IsPublicSuffix)
        {
            return;
        }

        DnsPropagationSet.Reset(domainName);

        var recordTypes = (DnsPropagationRecordTypes != null && DnsPropagationRecordTypes.Length > 0)
            ? DnsPropagationRecordTypes.Distinct().ToArray()
            : new[] { DnsRecordType.A, DnsRecordType.AAAA };

        var analysis = new DnsPropagationAnalysis();
        analysis.LoadBuiltinServers();

        var available = analysis.FilterServers().Where(s => s.Enabled).ToList();
        var maxServers = Math.Max(0, DnsPropagationMaxServers);
        var selected = SelectServersDistributed(available, maxServers <= 0 ? available.Count : maxServers);

        if (selected.Count == 0)
        {
            // Still emit one report analysis so the caller gets a meaningful finding.
            var empty = new DnsPropagationReportAnalysis();
            empty.Load(domainName, recordTypes.FirstOrDefault(), Array.Empty<DnsPropagationResult>(), maxResultsToKeep: DnsPropagationMaxResultsToKeep);
            DnsPropagationSet.Add(empty);
            return;
        }

        var maxParallel = Math.Max(1, DnsPropagationMaxParallelism);
        foreach (var recordType in recordTypes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var results = await analysis.QueryAsync(
                domainName,
                recordType,
                selected,
                cancellationToken,
                progress: null,
                maxParallelism: maxParallel,
                includeGeo: DnsPropagationIncludeGeo).ConfigureAwait(false);

            var report = new DnsPropagationReportAnalysis();
            report.Load(domainName, recordType, results, maxResultsToKeep: DnsPropagationMaxResultsToKeep);
            DnsPropagationSet.Add(report);
        }
    }

    private static List<PublicDnsEntry> SelectServersDistributed(IReadOnlyList<PublicDnsEntry> servers, int max)
    {
        if (servers == null || servers.Count == 0 || max <= 0)
        {
            return new List<PublicDnsEntry>();
        }

        var byCountry = servers
            .Where(s => s != null && s.Enabled)
            .GroupBy(s => s.Country)
            .OrderBy(g => g.Key.ToString(), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderBy(x => x.Location.ToString()).ThenBy(x => x.IPAddress.ToString(), StringComparer.OrdinalIgnoreCase).ToList())
            .ToList();

        var selected = new List<PublicDnsEntry>(Math.Min(max, servers.Count));
        var idx = 0;
        while (selected.Count < max)
        {
            var addedAny = false;
            foreach (var group in byCountry)
            {
                if (idx < group.Count)
                {
                    selected.Add(group[idx]);
                    if (selected.Count >= max) break;
                    addedAny = true;
                }
            }
            if (!addedAny) break;
            idx++;
        }

        return selected;
    }
}

