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
                    try {
                        int? ttl = await AuthoritativeTtlOverride(request.Owner, request.Type).ConfigureAwait(false);
                        if (ttl.HasValue) { observed.TryAdd(request.Label, ttl.Value); }
                        return true;
                    } catch (Exception error) when (Helpers.AuthoritativeDnsProbes.IsTransportFailure(error)) {
                        token.ThrowIfCancellationRequested();
                        return false;
                    }
                }, concurrency: 8, cancellationToken: deadline.Token).ConfigureAwait(false);
            } else if (requests.Count > 0) {
                await CollectAuthoritativeTtlValuesAsync(nsRecords,
                    requests.Select(request => (request.Label, request.Owner, request.Type)).ToArray(),
                    observed, budget, deadline.Token, token).ConfigureAwait(false);
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
