using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DNSBLAnalysis {
    /// <summary>Discovers every selected address family before slow provider checks can exhaust the run budget.</summary>
    private async Task<List<(string Ip, string Host, DnsblIpSource Source)>> DiscoverTargetsAsync(
        string domainName, DomainIpScanMode mode, QueryRun run, InternalLogger? logger) {
        if (!Enum.IsDefined(typeof(DomainIpScanMode), mode)) { mode = DomainIpScanMode.MxThenApexFallback; }
        bool includeMx = mode != DomainIpScanMode.ApexOnly && mode != DomainIpScanMode.ApexAOnly && mode != DomainIpScanMode.ApexAAAAOnly;
        bool includeApex = !includeMx || mode == DomainIpScanMode.MxAndApex;
        bool includeA = mode != DomainIpScanMode.MxAAAAOnly && mode != DomainIpScanMode.ApexAAAAOnly;
        bool includeAaaa = mode != DomainIpScanMode.MxAOnly && mode != DomainIpScanMode.ApexAOnly;

        async Task<List<(string Ip, string Host, DnsblIpSource Source)>> ResolveHostsAsync(string[] hosts, bool mx) {
            var requests = new List<(string Host, DnsRecordType Type, DnsblIpSource Source)>();
            foreach (string host in hosts) {
                if (includeA) { requests.Add((host, DnsRecordType.A, mx ? DnsblIpSource.MxA : DnsblIpSource.ApexA)); }
                if (includeAaaa) { requests.Add((host, DnsRecordType.AAAA, mx ? DnsblIpSource.MxAAAA : DnsblIpSource.ApexAAAA)); }
            }
            var results = await Helpers.BoundedAsync.RunAsync(requests, async request => {
                var answers = await QueryDiscoveryAsync(run, request.Host, request.Type, logger, request.Source).ConfigureAwait(false);
                return answers.Select(answer => (Ip: answer.Data, Host: request.Host, Source: request.Source)).ToArray();
            }, Math.Min(8, run.MaxParallelism), run.CallerToken).ConfigureAwait(false);
            // Preserve the prior source grouping, then hostname/input order, while discovery overlaps.
            return results.SelectMany(result => result).OrderBy(result => result.Source).ToList();
        }

        async Task<List<(string Ip, string Host, DnsblIpSource Source)>> ResolveMxAsync() {
            if (!includeMx) { return new(); }
            var sources = includeA && includeAaaa ? new[] { DnsblIpSource.MxA, DnsblIpSource.MxAAAA }
                : new[] { includeA ? DnsblIpSource.MxA : DnsblIpSource.MxAAAA };
            var records = await QueryDiscoveryAsync(run, domainName, DnsRecordType.MX, logger, sources).ConfigureAwait(false);
            var hosts = new List<string>();
            foreach (var record in records) {
                string data = (record.Data ?? string.Empty).Trim();
                if (string.IsNullOrEmpty(data)) { continue; }
                var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string host = (parts.Length >= 2 ? parts[1] : parts[0]).Trim().TrimEnd('.');
                if (!string.IsNullOrWhiteSpace(host)) { hosts.Add(host); }
            }
            return await ResolveHostsAsync(hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), mx: true).ConfigureAwait(false);
        }

        var mxTask = ResolveMxAsync();
        var apexTask = includeApex ? ResolveHostsAsync(new[] { domainName }, mx: false)
            : Task.FromResult(new List<(string Ip, string Host, DnsblIpSource Source)>());
        await Task.WhenAll(mxTask, apexTask).ConfigureAwait(false);
        var targets = await mxTask;
        targets.AddRange(await apexTask);
        if (mode == DomainIpScanMode.MxThenApexFallback && targets.Count == 0) {
            logger?.WriteVerbose("No IPs resolved from MX hosts; falling back to apex A/AAAA.");
            targets.AddRange(await ResolveHostsAsync(new[] { domainName }, mx: false).ConfigureAwait(false));
        }
        return targets;
    }
}
