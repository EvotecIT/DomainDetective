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

    private async Task UseAuthoritativeTtlsAsync(string domain, DnsAnswer[] nsRecords, InternalLogger logger, CancellationToken token) {
        var requests = new List<(string Label, string Owner, DnsRecordType Type, IReadOnlyList<int> Values, Action<int[]> Apply)> {
            ("A", domain, DnsRecordType.A, ATtls, values => ATtls = values),
            ("AAAA", domain, DnsRecordType.AAAA, AaaaTtls, values => AaaaTtls = values),
            ("MX", domain, DnsRecordType.MX, MxTtls, values => MxTtls = values),
            ("NS", domain, DnsRecordType.NS, NsTtls, values => NsTtls = values),
            ("SOA", domain, DnsRecordType.SOA, SoaTtl > 0 ? new[] { SoaTtl } : Array.Empty<int>(), values => SoaTtl = values[0]),
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
        IPAddress? server = null;
        var observed = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        try {
            if (AuthoritativeTtlOverride == null) {
                var hosts = nsRecords.Where(answer => answer.Type == DnsRecordType.NS)
                    .Select(answer => answer.Data.Trim().TrimEnd('.')).Where(host => host.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                var queries = hosts.SelectMany(host => new[] { (host, DnsRecordType.A), (host, DnsRecordType.AAAA) });
                using var discovery = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                var addresses = new ConcurrentQueue<IPAddress>();
                try {
                    await Helpers.AuthoritativeDnsProbes.RunAsync(queries, async query => {
                        try {
                            var answers = await QueryDns(query.Item1, query.Item2, discovery.Token).ConfigureAwait(false);
                            foreach (var answer in answers.Where(answer => answer.Type == query.Item2)) {
                                if (!IPAddress.TryParse(answer.Data, out var ip)) { continue; }
                                addresses.Enqueue(ip);
                                discovery.Cancel();
                                break;
                            }
                        } catch (Exception exception) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(exception)) {
                            token.ThrowIfCancellationRequested();
                        }
                        return true;
                    }, concurrency: 8, cancellationToken: discovery.Token).ConfigureAwait(false);
                } catch (OperationCanceledException) when (discovery.IsCancellationRequested) { token.ThrowIfCancellationRequested(); }
                addresses.TryPeek(out server);
                if (server == null) { return; }
            }
            await Helpers.AuthoritativeDnsProbes.RunAsync(requests, async request => {
                try {
                    int? ttl = AuthoritativeTtlOverride != null
                        ? await AuthoritativeTtlOverride(request.Owner, request.Type).ConfigureAwait(false)
                        : (await QueryTtlFromServer(server!, request.Owner, (ushort)request.Type, deadline.Token, budget).ConfigureAwait(false)).Ttl;
                    if (ttl.HasValue) { observed[request.Label] = ttl.Value; }
                    return true;
                } catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception exception) when (exception is OperationCanceledException || exception is TimeoutException
                    || exception is System.Net.Sockets.SocketException || exception is DnsClientException) {
                    return false;
                }
            }, concurrency: 8, cancellationToken: deadline.Token).ConfigureAwait(false);
        } catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
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
