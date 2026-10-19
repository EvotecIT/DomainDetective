using DnsClientX;
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DnsTtlAnalysis {
    /// <summary>Optional fixed authoritative TTL source; null means no authoritative value is known.</summary>
    public Func<string, DnsRecordType, Task<int?>>? AuthoritativeTtlOverride { private get; set; }
    /// <summary>Whether all evaluated TTL sets came from authoritative or fixed replay evidence.</summary>
    public bool TtlsFromAuthoritativeServers { get; private set; }
    private readonly HashSet<string> _authoritativeTtlLabels = new(StringComparer.Ordinal);

    private async Task UseAuthoritativeTtlsAsync(string domain, DnsAnswer[] nsRecords, bool hasSoaRecord, InternalLogger logger, CancellationToken token) {
        var requests = new List<(string Label, string Owner, DnsRecordType Type, IReadOnlyList<int> Values, Action<int[]> Apply)> {
            ("A", domain, DnsRecordType.A, ATtls, values => ATtls = values),
            ("AAAA", domain, DnsRecordType.AAAA, AaaaTtls, values => AaaaTtls = values),
            ("MX", domain, DnsRecordType.MX, MxTtls, values => MxTtls = values),
            ("NS", domain, DnsRecordType.NS, NsTtls, values => NsTtls = values),
            ("SOA", domain, DnsRecordType.SOA, hasSoaRecord ? new[] { SoaTtl } : Array.Empty<int>(), values => SoaTtl = values[0]),
            ("SPF TXT", domain, DnsRecordType.TXT, SpfTxtTtls, values => SpfTxtTtls = values),
            ("DMARC TXT", $"_dmarc.{domain}", DnsRecordType.TXT, DmarcTxtTtls, values => DmarcTxtTtls = values),
            ("MTA-STS TXT", $"_mta-sts.{domain}", DnsRecordType.TXT, MtastsTxtTtls, values => MtastsTxtTtls = values),
            ("TLS-RPT TXT", $"_smtp._tls.{domain}", DnsRecordType.TXT, TlsRptTxtTtls, values => TlsRptTxtTtls = values)
        };
        foreach (var item in DkimTxtTtls) {
            string owner = item.Key;
            string selector = owner.Substring(0, owner.IndexOf("._domainkey.", StringComparison.OrdinalIgnoreCase));
            requests.Add(($"DKIM TXT ({selector})", owner, DnsRecordType.TXT, item.Value, values => DkimTxtTtls[owner] = values));
        }
        requests.RemoveAll(request => request.Values.Count == 0);
        if (AuthoritativeTtlOverride == null && (QueryDnsOverride != null || DnsConfiguration.QueryDnsOverride != null)) {
            foreach (var request in requests) { _authoritativeTtlLabels.Add(request.Label); }
            TtlsFromAuthoritativeServers = true;
            return;
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        int budget = UniformityQueryTimeoutMs > 0 ? UniformityQueryTimeoutMs : 4000;
        deadline.CancelAfter(budget);
        var observed = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        try {
            if (AuthoritativeTtlOverride != null) {
                await Helpers.AuthoritativeDnsProbes.RunAsync(requests, async request => {
                    int? ttl = await AuthoritativeTtlOverride(request.Owner, request.Type).ConfigureAwait(false);
                    if (ttl.HasValue) { observed.TryAdd(request.Label, ttl.Value); }
                    return true;
                }, concurrency: 8, cancellationToken: deadline.Token).ConfigureAwait(false);
            } else if (requests.Count > 0) {
                var hosts = nsRecords.Where(answer => answer.Type == DnsRecordType.NS)
                    .Select(answer => answer.Data.Trim().TrimEnd('.')).Where(host => host.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                var queries = hosts.SelectMany(host => new[] { (host, DnsRecordType.A), (host, DnsRecordType.AAAA) });
                using var alternatives = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var probes = new SemaphoreSlim(8);
                var attempted = new ConcurrentDictionary<IPAddress, byte>();
                async Task ReadServer(IPAddress server) {
                    await Helpers.AuthoritativeDnsProbes.RunAsync(requests, async request => {
                        if (observed.ContainsKey(request.Label)) { return true; }
                        await probes.WaitAsync(alternatives.Token).ConfigureAwait(false);
                        try {
                            if (observed.ContainsKey(request.Label)) { return true; }
                            var result = await QueryTtlFromServer(server, request.Owner, (ushort)request.Type,
                                alternatives.Token, budget, requireMatchingRrset: true).ConfigureAwait(false);
                            if (result.Ttl.HasValue) {
                                observed.TryAdd(request.Label, result.Ttl.Value);
                                if (observed.Count == requests.Count) { alternatives.Cancel(); }
                            }
                            return true;
                        } catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) {
                            token.ThrowIfCancellationRequested();
                            return false;
                        } finally { probes.Release(); }
                    }, concurrency: 8, cancellationToken: alternatives.Token).ConfigureAwait(false);
                }
                try {
                    await Helpers.AuthoritativeDnsProbes.RunAsync(queries, async query => {
                        try {
                            var answers = await QueryDns(query.Item1, query.Item2, alternatives.Token).ConfigureAwait(false);
                            var addresses = answers.Where(answer => answer.Type == query.Item2)
                                .Select(answer => IPAddress.TryParse(answer.Data, out var ip) ? ip : null)
                                .Where(ip => ip != null && attempted.TryAdd(ip, 0)).Cast<IPAddress>().ToArray();
                            await Helpers.AuthoritativeDnsProbes.RunAsync(addresses, async address => {
                                await ReadServer(address).ConfigureAwait(false);
                                return true;
                            }, concurrency: 8, cancellationToken: alternatives.Token).ConfigureAwait(false);
                        } catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) {
                            token.ThrowIfCancellationRequested();
                        }
                        return true;
                    }, concurrency: 8, cancellationToken: alternatives.Token).ConfigureAwait(false);
                } catch (OperationCanceledException) when (alternatives.IsCancellationRequested && !deadline.IsCancellationRequested) {
                    token.ThrowIfCancellationRequested();
                }
            }
        } catch (OperationCanceledException) when (token.IsCancellationRequested) { throw new OperationCanceledException(token); }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested) {
            logger?.WriteVerbose("Authoritative TTL value collection reached its budget; unverified cache countdowns are not judged too short.");
        } finally {
            foreach (var request in requests) {
                if (!observed.TryGetValue(request.Label, out var ttl)) { continue; }
                request.Apply(Enumerable.Repeat(ttl, request.Values.Count).ToArray());
                _authoritativeTtlLabels.Add(request.Label);
            }
            TtlsFromAuthoritativeServers = requests.Count > 0 && _authoritativeTtlLabels.Count == requests.Count;
        }
    }
}
