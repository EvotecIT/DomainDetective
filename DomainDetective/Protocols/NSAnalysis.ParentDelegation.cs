using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class NSAnalysis {
    /// <summary>Overall budget for locating and probing a usable parent authority.</summary>
    public TimeSpan ParentDelegationTimeout { get; set; } = TimeSpan.FromSeconds(5);
    /// <summary>Address of the parent authority that supplied the observed delegation; null for an injected full response.</summary>
    public string? ParentAuthorityServer { get; private set; }

    private async Task<DnsResponse> QueryParentDelegationResponseAsync(string domain, InternalLogger logger, CancellationToken ct) {
        if (ParentDelegationTimeout <= TimeSpan.Zero) { throw new ArgumentOutOfRangeException(nameof(ParentDelegationTimeout)); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(ParentDelegationTimeout);
        var token = deadline.Token;
        try {
            // A custom full-response transport explicitly supplies the parent evidence.
            if (QueryDnsFullOverride != null) {
                var supplied = (await QueryFullDns(domain, DnsRecordType.NS, token).ConfigureAwait(false)).FirstOrDefault();
                token.ThrowIfCancellationRequested();
                return supplied ?? throw new TimeoutException("No parent delegation response was supplied.");
            }

            string parent = GetParentZone(domain) ?? throw new TimeoutException("The DNS root has no parent delegation.");
            string? zone;
            if (parent == ".") { zone = parent; }
            else {
                var soa = await DnsConfiguration.QueryDNSResponse(parent, DnsRecordType.SOA, cancellationToken: token).ConfigureAwait(false);
                DnsConfiguration.EnsureConclusiveResponse(parent, DnsRecordType.SOA, soa);
                zone = AuthoritativeDnsProbes.GetEnclosingSoaZone(parent, soa, includeRoot: true);
            }
            if (zone == null) { throw new TimeoutException("The parent authoritative zone could not be discovered."); }
            var servers = await DnsConfiguration.QueryPolicyDNS(zone, DnsRecordType.NS, cancellationToken: token).ConfigureAwait(false);
            var names = servers.Where(answer => answer.Type == DnsRecordType.NS).Select(answer => answer.Data.TrimEnd('.'))
                .Where(name => name.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var resolved = await AuthoritativeDnsProbes.RunAsync(names, async name => {
                var a = QueryNsEvidenceAsync(name, DnsRecordType.A, token);
                var aaaa = QueryNsEvidenceAsync(name, DnsRecordType.AAAA, token);
                await Task.WhenAll(a, aaaa).ConfigureAwait(false);
                return (Name: name, A: await a, Aaaa: await aaaa);
            }, 4, token).ConfigureAwait(false);
            foreach (var server in resolved) {
                RecordQueryError(server.Name, DnsRecordType.A, server.A.Error, logger, parent: true);
                RecordQueryError(server.Name, DnsRecordType.AAAA, server.Aaaa.Error, logger, parent: true);
            }
            var addresses = resolved.SelectMany(server => server.A.Answers.Concat(server.Aaaa.Answers))
                .Select(answer => IPAddress.TryParse(answer.Data, out var ip) ? ip : null).Where(ip => ip != null)
                .Select(ip => ip!.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (addresses.Length == 0) { throw new TimeoutException("No usable parent authority address was discovered."); }

            var winner = new TaskCompletionSource<(DnsResponse Response, string Server)>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var probes = CancellationTokenSource.CreateLinkedTokenSource(token);
            try {
                await AuthoritativeDnsProbes.RunAsync(addresses, async address => {
                    var response = QueryResponseOverride == null
                        ? await AuthoritativeDnsProbes.QueryAsync(address, domain, DnsRecordType.NS, cancellationToken: probes.Token, acceptReferral: true).ConfigureAwait(false)
                        : await QueryResponseOverride(IPAddress.Parse(address), new DnsMessage(domain, DnsRecordType.NS,
                            new DnsMessageOptions(RecursionDesired: false)), probes.Token).ConfigureAwait(false);
                    probes.Token.ThrowIfCancellationRequested();
                    if (response != null && AuthoritativeDnsProbes.IsUsableResponse(response)
                        && (response.Answers ?? Array.Empty<DnsAnswer>()).Concat(response.Authorities ?? Array.Empty<DnsAnswer>())
                            .Any(answer => answer.Type == DnsRecordType.NS && string.Equals(answer.Name?.TrimEnd('.'), domain.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))) {
                        if (winner.TrySetResult((response, address))) { probes.Cancel(); }
                    }
                    return true;
                }, 8, probes.Token).ConfigureAwait(false);
            } catch (OperationCanceledException) when (!ct.IsCancellationRequested && winner.Task.IsCompleted) { }
            ct.ThrowIfCancellationRequested();
            token.ThrowIfCancellationRequested();
            if (!winner.Task.IsCompleted) { throw new TimeoutException("No usable parent delegation response was observed."); }
            var observed = await winner.Task.ConfigureAwait(false);
            ParentAuthorityServer = observed.Server;
            return observed.Response;
        } catch (OperationCanceledException) when (!ct.IsCancellationRequested) {
            throw new TimeoutException("Parent delegation discovery or probes exceeded their time budget.");
        }
    }
}
