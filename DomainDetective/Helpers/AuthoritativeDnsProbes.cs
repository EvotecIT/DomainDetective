using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Runs bounded direct DNS probes while retaining missing responses as unavailable evidence.</summary>
internal static class AuthoritativeDnsProbes {
    internal static async Task<TOutput[]> RunAsync<TInput, TOutput>(IEnumerable<TInput> inputs,
        Func<TInput, Task<TOutput>> probe, int concurrency = 8, CancellationToken cancellationToken = default) {
        return await BoundedAsync.RunAsync(inputs as IReadOnlyList<TInput> ?? inputs.ToArray(),
            probe, concurrency, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<DnsResponse?> QueryAsync(string address, string owner, DnsRecordType type,
        int timeoutMs = 2000, CancellationToken cancellationToken = default, bool acceptRefused = false, bool acceptReferral = false) {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeoutMs);
        try {
            cancellationToken.ThrowIfCancellationRequested();
            // Callers supply addresses from authoritative A/AAAA records. Invalid data must
            // remain unavailable rather than starting a new recursive server-name lookup.
            if (!IPAddress.TryParse(address, out _)) { return null; }
            var query = new DnsMessage(owner, type, new DnsMessageOptions(RecursionDesired: false));
            var result = await DnsWireQueryClient.QueryUdpAsync(address, 53, query, timeoutMs,
                useTcpFallback: true, cancellationToken: deadline.Token).ConfigureAwait(false);
            var response = result.Response;
            return (acceptReferral ? IsUsableResponse(response)
                : acceptRefused ? IsUsableResponse(response, acceptRefused: true) : IsAuthoritativeResponse(response)) ? response : null;
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is TimeoutException || ex is OperationCanceledException || ex is SocketException || ex is System.IO.IOException || ex is ArgumentException || ex is FormatException || ex is DnsClientException) {
            cancellationToken.ThrowIfCancellationRequested();
            return null;
        }
    }

    internal static bool IsUsableResponse(DnsResponse response, bool acceptRefused = false) =>
        string.IsNullOrEmpty(response.Error) && (response.Status == DnsResponseCode.NoError ||
            response.Status == DnsResponseCode.NXDomain || acceptRefused && response.Status == DnsResponseCode.Refused);

    internal static bool IsAuthoritativeResponse(DnsResponse? response) =>
        response != null && response.IsAuthoritativeAnswer && IsUsableResponse(response);

    /// <summary>Selects the closest enclosing SOA owner from a recursive answer or negative response.</summary>
    internal static string? GetEnclosingSoaZone(string owner, DnsResponse response, bool includeRoot = false) {
        string normalized = owner.Trim().TrimEnd('.');
        return (response.Answers ?? Array.Empty<DnsAnswer>()).Concat(response.Authorities ?? Array.Empty<DnsAnswer>())
            .Where(answer => answer.Type == DnsRecordType.SOA)
            .Select(answer => (answer.Name ?? string.Empty).Trim().TrimEnd('.'))
            .Where(zone => zone.Length > 0 && (normalized.Equals(zone, StringComparison.OrdinalIgnoreCase)
                || normalized.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase)) || includeRoot && zone.Length == 0)
            .OrderByDescending(zone => zone.Length).Select(zone => zone.Length == 0 ? "." : zone).FirstOrDefault();
    }

    internal static void ReportIpv6Reachability(IEnumerable<string> attempted, IEnumerable<string> reachable, InternalLogger logger) {
        var addresses = attempted.Select(value => IPAddress.TryParse(value, out var address) ? address : null).Where(address => address != null).ToArray();
        var replies = reachable.Select(value => IPAddress.TryParse(value, out var address) ? address : null).Where(address => address != null).ToArray();
        if (addresses.Any(address => address!.AddressFamily == AddressFamily.InterNetworkV6) &&
            !replies.Any(address => address!.AddressFamily == AddressFamily.InterNetworkV6) &&
            replies.Any(address => address!.AddressFamily == AddressFamily.InterNetwork)) {
            logger.WriteInformationCode("DNS.Authoritative.IPv6.NoUsableResponse", "No usable authoritative DNS response was observed via IPv6 from this probe; IPv4 responded.");
        }
    }
}
