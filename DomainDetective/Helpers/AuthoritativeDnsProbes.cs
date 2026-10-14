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
        using var gate = new SemaphoreSlim(Math.Max(1, concurrency));
        return await Task.WhenAll(inputs.Select(async input => {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try { return await probe(input).ConfigureAwait(false); }
            finally { gate.Release(); }
        })).ConfigureAwait(false);
    }

    internal static async Task<DnsResponse?> QueryAsync(string address, string owner, DnsRecordType type,
        int timeoutMs = 2000, CancellationToken cancellationToken = default) {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeoutMs);
        try {
            var query = new DnsMessage(owner, type, new DnsMessageOptions(RecursionDesired: false));
            var result = await DnsWireQueryClient.QueryUdpAsync(address, 53, query, timeoutMs,
                useTcpFallback: true, cancellationToken: deadline.Token).ConfigureAwait(false);
            var response = result.Response;
            return string.IsNullOrEmpty(response.Error) &&
                (response.Status == DnsResponseCode.NoError || response.Status == DnsResponseCode.NXDomain) ? response : null;
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is TimeoutException || ex is OperationCanceledException || ex is SocketException || ex is System.IO.IOException) {
            return null;
        }
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
