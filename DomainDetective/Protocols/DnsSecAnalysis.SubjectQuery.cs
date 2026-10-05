using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DnsSecAnalysis {
    /// <summary>
    /// Queries one RRset with local DNSSEC validation, without the metadata probes
    /// performed by a full DNSSEC report. Full-response overrides retain their
    /// supplied validation status for deterministic callers.
    /// </summary>
    internal static async Task<DnsResponse> QueryValidatedSubjectResponseAsync(
        string name, DnsRecordType type, DnsConfiguration configuration, CancellationToken cancellationToken) {
        if (configuration.QueryDnsResponseOverride != null) {
            return await configuration.QueryDnsResponseOverride(name, type, cancellationToken).ConfigureAwait(false);
        }

        if (configuration.QueryDnsOverride != null) {
            throw new InvalidOperationException("An answer-only DNS override cannot provide DNSSEC validation status.");
        }

        DnsEndpoint[] endpoints = configuration.DnsEndpoints.Count > 0
            ? configuration.DnsEndpoints.Distinct().ToArray()
            : new[] { configuration.DnsEndpoint };
        using DnsMultiResolver resolver = CreateResolver(endpoints, configuration, validateDnsSec: true);
        return await resolver.QueryAsync(name, type, cancellationToken).ConfigureAwait(false);
    }
}
