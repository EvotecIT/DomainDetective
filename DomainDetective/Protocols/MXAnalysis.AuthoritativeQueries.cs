using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class MXAnalysis {
    private readonly Func<string, string, DnsRecordType, CancellationToken, Task<DnsResponse?>> _queryAuthoritative;

    /// <summary>Creates MX analysis using native authoritative DNS probes.</summary>
    public MXAnalysis() : this((server, owner, type, token) =>
        Helpers.AuthoritativeDnsProbes.QueryAsync(server, owner, type, cancellationToken: token)) { }

    /// <summary>Supplies the direct DNS transport boundary while retaining normal zone discovery.</summary>
    internal MXAnalysis(Func<string, string, DnsRecordType, CancellationToken, Task<DnsResponse?>> queryAuthoritative) {
        _queryAuthoritative = queryAuthoritative ?? throw new ArgumentNullException(nameof(queryAuthoritative));
    }

    private async Task CheckCrossNsConsistencyAsync(string domain, IEnumerable<string> mxHosts, InternalLogger logger,
        AssessmentCollector collector, CancellationToken cancellationToken) {
        if (DnsConfiguration.QueryDnsOverride != null) {
            logger.WriteVerbose("Skipping MX cross-NS consistency checks because DNS queries are running through an override.");
            return;
        }
        var targets = mxHosts.Select(NormalizeHost).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var authorities = await DiscoverComparisonAuthoritiesAsync(domain, targets, cancellationToken).ConfigureAwait(false);
        var discovery = authorities[NormalizeHost(domain)];
        var requests = new List<(string Owner, string Server, DnsRecordType Type)>();
        requests.AddRange(discovery.Addresses.Select(server => (domain, server, DnsRecordType.MX)));
        foreach (string host in targets) {
            foreach (string server in authorities[host].Addresses) {
                requests.Add((host, server, DnsRecordType.A));
                requests.Add((host, server, DnsRecordType.AAAA));
            }
        }

        // One admission slot owns one question, including its transport fallback.
        // Slow endpoints cannot multiply the concurrency limit through nested batches.
        int concurrency = Math.Max(1, Math.Min(AuthoritativeMaxParallelism,
            DnsConfiguration.ResolverMaxConcurrency ?? int.MaxValue));
        var responses = await Helpers.AuthoritativeDnsProbes.RunAsync(requests, async request => {
            var response = await _queryAuthoritative(request.Server, request.Owner, request.Type, cancellationToken).ConfigureAwait(false);
            return (request.Owner, request.Server, request.Type, Response: response);
        }, concurrency, cancellationToken).ConfigureAwait(false);

        var mxByServer = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in responses.Where(item => item.Type == DnsRecordType.MX)) {
            if (!Helpers.AuthoritativeDnsProbes.IsAuthoritativeResponse(item.Response)) { continue; }
            mxByServer[item.Server] = new HashSet<string>((item.Response!.Answers ?? Array.Empty<DnsAnswer>())
                .Select(answer => FormatMx(answer.Data)), StringComparer.OrdinalIgnoreCase);
        }
        Helpers.AuthoritativeDnsProbes.ReportIpv6Reachability(discovery.Addresses, mxByServer.Keys, logger);
        RecordRrsetCompleteness(discovery.Addresses.Count, mxByServer.Count, domain, logger, collector, discovery.Incomplete);
        RecordRrsetConsistency(domain, mxByServer.Values, logger, collector);

        var byOwner = responses.Where(item => item.Type != DnsRecordType.MX).ToLookup(item => item.Owner, StringComparer.OrdinalIgnoreCase);
        TargetAddressComparisonIncomplete = false;
        foreach (string host in targets) {
            var families = byOwner[host].GroupBy(item => item.Server, StringComparer.OrdinalIgnoreCase).Select(server => (
                A: server.First(item => item.Type == DnsRecordType.A).Response,
                Aaaa: server.First(item => item.Type == DnsRecordType.AAAA).Response));
            RecordTargetAddressEvidence(host, families, logger, collector, authorities[host].Incomplete);
        }
    }
}
