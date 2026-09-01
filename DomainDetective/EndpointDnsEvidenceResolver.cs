using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>DNS evidence associated with one logical service endpoint.</summary>
public sealed class EndpointDnsEvidence {
    /// <summary>Logical hostname requested by the caller.</summary>
    public string HostName { get; init; } = string.Empty;

    /// <summary>Final CNAME target, or the original hostname when no CNAME exists.</summary>
    public string EffectiveHostName { get; init; } = string.Empty;

    /// <summary>CNAME targets in traversal order.</summary>
    public IReadOnlyList<string> CnameChain { get; init; } = Array.Empty<string>();

    /// <summary>IPv4 and IPv6 addresses resolved for the effective hostname.</summary>
    public IReadOnlyList<string> Addresses { get; init; } = Array.Empty<string>();

    /// <summary>True when both A and AAAA lookups completed, including valid empty answers.</summary>
    public bool AddressResolutionComplete { get; init; }

    /// <summary>DNS endpoint used by the resolver.</summary>
    public string Resolver { get; init; } = string.Empty;

    /// <summary>Time at which DNS evidence was observed.</summary>
    public DateTimeOffset ObservedAtUtc { get; init; }

    /// <summary>True when a CNAME loop was encountered.</summary>
    public bool LoopDetected { get; init; }

    /// <summary>Non-fatal lookup or parsing errors.</summary>
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
}

/// <summary>Resolves CNAME chains and endpoint addresses as reusable classification evidence.</summary>
public sealed class EndpointDnsEvidenceResolver {
    /// <summary>DNS configuration used for all queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Maximum number of CNAME links followed before the result is treated as incomplete.</summary>
    public int MaxCnameDepth { get; set; } = 16;

    /// <summary>
    /// Whether A and AAAA queries are performed for the original hostname when no CNAME target is found.
    /// Endpoint-enrichment callers normally keep this enabled; CNAME-only analysis can disable it.
    /// </summary>
    public bool ResolveAddressesForOriginalHost { get; set; } = true;

    /// <summary>Optional query override for deterministic callers and tests.</summary>
    public Func<string, DnsRecordType, CancellationToken, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Resolves endpoint DNS evidence without discarding partial results on lookup failure.</summary>
    public async Task<EndpointDnsEvidence> ResolveAsync(
        string hostName,
        CancellationToken cancellationToken = default) {
        string normalizedHost = NormalizeHost(hostName);
        if (normalizedHost.Length == 0) {
            throw new ArgumentException("A logical hostname is required.", nameof(hostName));
        }
        if (MaxCnameDepth < 1 || MaxCnameDepth > 128) {
            throw new ArgumentOutOfRangeException(nameof(MaxCnameDepth), "MaxCnameDepth must be between 1 and 128.");
        }

        if (IPAddress.TryParse(normalizedHost, out IPAddress? literalAddress) && literalAddress != null) {
            IPAddress normalizedAddress = literalAddress.IsIPv4MappedToIPv6
                ? literalAddress.MapToIPv4()
                : literalAddress;
            return new EndpointDnsEvidence {
                HostName = normalizedHost,
                EffectiveHostName = normalizedHost,
                Addresses = new[] { normalizedAddress.ToString() },
                AddressResolutionComplete = true,
                Resolver = DnsConfiguration.DnsEndpoint.ToString(),
                ObservedAtUtc = DateTimeOffset.UtcNow
            };
        }

        var chain = new List<string>();
        var errors = new List<string>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { normalizedHost };
        string current = normalizedHost;
        bool loopDetected = false;

        for (int depth = 0; depth < MaxCnameDepth; depth++) {
            cancellationToken.ThrowIfCancellationRequested();
            DnsAnswer[] answers;
            try {
                answers = await QueryAsync(current, DnsRecordType.CNAME, cancellationToken).ConfigureAwait(false);
            } catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested) {
                errors.Add($"CNAME lookup for '{current}' failed: {ex.Message}");
                break;
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                errors.Add($"CNAME lookup for '{current}' failed: {ex.Message}");
                break;
            }

            string next = SelectCnameTarget(current, answers, out bool ambiguousCname);
            if (ambiguousCname) {
                errors.Add($"CNAME lookup for '{current}' returned multiple distinct targets.");
            }
            if (next.Length == 0) {
                break;
            }
            if (!visited.Add(next)) {
                loopDetected = true;
                errors.Add($"CNAME loop detected at '{next}'.");
                break;
            }

            chain.Add(next);
            current = next;
            if (depth == MaxCnameDepth - 1) {
                errors.Add($"CNAME chain exceeded MaxCnameDepth={MaxCnameDepth}.");
            }
        }

        if (chain.Count == 0 && !ResolveAddressesForOriginalHost) {
            return new EndpointDnsEvidence {
                HostName = normalizedHost,
                EffectiveHostName = current,
                CnameChain = chain,
                AddressResolutionComplete = false,
                Resolver = DnsConfiguration.DnsEndpoint.ToString(),
                ObservedAtUtc = DateTimeOffset.UtcNow,
                LoopDetected = loopDetected,
                Errors = errors
            };
        }

        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int completedAddressLookups = 0;
        foreach (DnsRecordType type in new[] { DnsRecordType.A, DnsRecordType.AAAA }) {
            cancellationToken.ThrowIfCancellationRequested();
            try {
                DnsAnswer[] answers = await QueryAsync(current, type, cancellationToken).ConfigureAwait(false);
                completedAddressLookups++;
                foreach (DnsAnswer answer in answers) {
                    string value = (answer.Data ?? answer.DataRaw ?? string.Empty).Trim();
                    if (IPAddress.TryParse(value, out IPAddress? address) && address != null) {
                        addresses.Add(address.ToString());
                    }
                }
            } catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested) {
                errors.Add($"{type} lookup for '{current}' failed: {ex.Message}");
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                errors.Add($"{type} lookup for '{current}' failed: {ex.Message}");
            }
        }

        return new EndpointDnsEvidence {
            HostName = normalizedHost,
            EffectiveHostName = current,
            CnameChain = chain,
            Addresses = addresses.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList(),
            AddressResolutionComplete = completedAddressLookups == 2,
            Resolver = DnsConfiguration.DnsEndpoint.ToString(),
            ObservedAtUtc = DateTimeOffset.UtcNow,
            LoopDetected = loopDetected,
            Errors = errors
        };
    }

    private Task<DnsAnswer[]> QueryAsync(
        string name,
        DnsRecordType recordType,
        CancellationToken cancellationToken) {
        if (QueryDnsOverride != null) {
            return QueryDnsOverride(name, recordType, cancellationToken);
        }
        return DnsConfiguration.QueryDNS(name, recordType, cancellationToken: cancellationToken);
    }

    private static string SelectCnameTarget(
        string current,
        IReadOnlyList<DnsAnswer> answers,
        out bool ambiguous) {
        ambiguous = false;
        string normalizedCurrent = NormalizeHost(current);
        string[] ownerTargets = answers
            .Where(answer => answer.Type == DnsRecordType.CNAME &&
                             NormalizeHost(answer.Name).Equals(normalizedCurrent, StringComparison.OrdinalIgnoreCase))
            .Select(answer => NormalizeHost(answer.Data ?? answer.DataRaw))
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .ToArray();
        if (ownerTargets.Length > 0) {
            ambiguous = ownerTargets.Length > 1;
            return ambiguous ? string.Empty : ownerTargets[0];
        }

        // Custom resolvers and older deterministic callers may omit the owner name.
        // They may also omit the record type because this is already a CNAME query.
        // Preserve that contract only when the ownerless response is unambiguous.
        string[] ownerlessTargets = answers
            .Where(answer => NormalizeHost(answer.Name).Length == 0)
            .Select(answer => NormalizeHost(answer.Data ?? answer.DataRaw))
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(2)
            .ToArray();
        ambiguous = ownerlessTargets.Length > 1;
        return ownerlessTargets.Length == 1 ? ownerlessTargets[0] : string.Empty;
    }

    private static string NormalizeHost(string? value) =>
        EndpointHostNormalizer.Normalize(value, lowercase: true);
}
