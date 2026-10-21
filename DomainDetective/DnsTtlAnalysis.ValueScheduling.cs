using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DnsTtlAnalysis {
    private sealed class TtlValueServer(IPAddress address, int requestCount) {
        internal IPAddress Address { get; } = address;
        internal Queue<int> Pending { get; } = new(Enumerable.Range(0, requestCount));
        internal bool Responsive;
        internal int Active;
    }

    private sealed class TtlValueProbe(TtlValueServer server, int index, CancellationTokenSource lifetime,
        Task<(int? Ttl, bool Succeeded)> query) {
        internal TtlValueServer Server { get; } = server;
        internal int Index { get; } = index;
        internal CancellationTokenSource Lifetime { get; } = lifetime;
        internal Task<(int? Ttl, bool Succeeded)> Query { get; } = query;
        internal bool Yielded;
    }

    // Values need one confirmed matching RRset; the separate uniformity phase
    // retains the cross-server matrix. Prefer confirmed sources without letting
    // a blackholed first address prevent another family from answering.
    private async Task CollectAuthoritativeTtlValuesAsync(DnsAnswer[] nsRecords,
        IReadOnlyList<(string Label, string Owner, DnsRecordType Type)> requests,
        ConcurrentDictionary<string, int> observed, int budget, CancellationToken deadline, CancellationToken caller) {
        var hosts = nsRecords.Where(answer => answer.Type == DnsRecordType.NS)
            .Select(answer => answer.Data.Trim().TrimEnd('.')).Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var addresses = new ConcurrentQueue<IPAddress>();
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(deadline);
        using var changed = new SemaphoreSlim(0);
        async Task Discover() {
            try {
                await Helpers.AuthoritativeDnsProbes.RunAsync(hosts.SelectMany(host => new[] { (host, DnsRecordType.A), (host, DnsRecordType.AAAA) }),
                    async query => {
                        try {
                            var answers = await QueryDns(query.host, query.Item2, stop.Token).ConfigureAwait(false);
                            foreach (var answer in answers.Where(answer => answer.Type == query.Item2)) {
                                if (!IPAddress.TryParse(answer.Data, out var address)) { continue; }
                                if ((query.Item2 == DnsRecordType.A) != (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)) { continue; }
                                addresses.Enqueue(address);
                                changed.Release();
                            }
                        } catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) { caller.ThrowIfCancellationRequested(); }
                        return true;
                    }, concurrency: 8, cancellationToken: stop.Token).ConfigureAwait(false);
            } finally { changed.Release(); }
        }
        async Task<(int? Ttl, bool Succeeded)> Probe(TtlValueServer server, int index, CancellationToken token) {
            try {
                var request = requests[index];
                var result = await QueryTtlFromServer(server.Address, request.Owner, (ushort)request.Type, token, budget,
                    requireMatchingRrset: true).ConfigureAwait(false);
                if (result.Ttl.HasValue) { observed.TryAdd(request.Label, result.Ttl.Value); }
                return result;
            } catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) {
                caller.ThrowIfCancellationRequested();
                return (null, false);
            }
        }
        var servers = new List<TtlValueServer>();
        var seen = new HashSet<IPAddress>();
        var active = new List<TtlValueProbe>();
        var discovery = Discover();
        Task notification = changed.WaitAsync(stop.Token);
        try {
            while (true) {
                stop.Token.ThrowIfCancellationRequested();
                while (addresses.TryDequeue(out var address)) {
                    if (seen.Add(address)) { servers.Add(new TtlValueServer(address, requests.Count)); }
                }
                foreach (var probe in active.Where(probe => probe.Query.IsCompleted).ToArray()) {
                    active.Remove(probe);
                    probe.Server.Active--;
                    try {
                        var result = await probe.Query.ConfigureAwait(false);
                        if (result.Ttl.HasValue) {
                            observed.TryAdd(requests[probe.Index].Label, result.Ttl.Value);
                        }
                        if (result.Succeeded) { probe.Server.Responsive = true; }
                        else if (probe.Yielded) { probe.Server.Pending.Enqueue(probe.Index); }
                    } finally { probe.Lifetime.Dispose(); }
                }
                if (observed.Count == requests.Count) { break; }
                if (discovery.IsCompleted) { await discovery.ConfigureAwait(false); }
                foreach (var server in servers) {
                    while (server.Pending.Count > 0 && observed.ContainsKey(requests[server.Pending.Peek()].Label)) { server.Pending.Dequeue(); }
                }
                int preferred = servers.Where(server => server.Responsive).Sum(server => server.Pending.Count);
                int slotsNeeded = Math.Min(8, preferred) - (8 - active.Count);
                // Yield speculative alternatives only when their slots are needed by
                // a source already returning matching evidence. Draining precedes reuse.
                foreach (var probe in active.Where(probe => !probe.Server.Responsive && !probe.Yielded)) {
                    if (slotsNeeded-- <= 0) { break; }
                    probe.Yielded = true;
                    probe.Lifetime.Cancel();
                }
                // Discovery can finish with a new address still queued since the
                // last drain. Keep slots available until that address is admitted.
                while (active.Count < 8) {
                    var server = servers.Where(server => server.Pending.Count > 0 &&
                            (server.Responsive || server.Active < 4 ||
                                servers.Count == 1 && discovery.IsCompleted && addresses.IsEmpty))
                        .OrderByDescending(server => server.Responsive).ThenBy(server => server.Active).FirstOrDefault();
                    if (server == null) { break; }
                    int index = server.Pending.Dequeue();
                    if (observed.ContainsKey(requests[index].Label)) { continue; }
                    var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop.Token);
                    server.Active++;
                    active.Add(new TtlValueProbe(server, index, lifetime, Probe(server, index, lifetime.Token)));
                }
                if (active.Count == 0 && discovery.IsCompleted && servers.All(server => server.Pending.Count == 0)) { break; }
                if (notification.IsCompleted) {
                    await notification.ConfigureAwait(false);
                    notification = changed.WaitAsync(stop.Token);
                    continue;
                }
                var waiting = active.Select(probe => (Task)probe.Query).Append(notification);
                if (!discovery.IsCompleted) { waiting = waiting.Append(discovery); }
                await Task.WhenAny(waiting).ConfigureAwait(false);
            }
        } finally {
            stop.Cancel();
            try { await discovery.ConfigureAwait(false); } catch (Exception) { /* Observe every owned discovery worker. */ }
            try { await Task.WhenAll(active.Select(probe => probe.Query)).ConfigureAwait(false); }
            finally {
                foreach (var probe in active) { probe.Lifetime.Dispose(); }
                try { await notification.ConfigureAwait(false); } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            }
        }
        caller.ThrowIfCancellationRequested();
    }
}
