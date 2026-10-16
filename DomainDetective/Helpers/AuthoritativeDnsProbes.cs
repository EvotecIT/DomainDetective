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
        var items = inputs.ToArray();
        var results = new TOutput[items.Length];
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        int next = -1;
        async Task RunWorkerAsync() {
            try {
                while (true) {
                    stop.Token.ThrowIfCancellationRequested();
                    int index = Interlocked.Increment(ref next);
                    if (index >= items.Length) { return; }
                    results[index] = await probe(items[index]).ConfigureAwait(false);
                }
            } catch { stop.Cancel(); throw; }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(items.Length, Math.Max(1, concurrency)))
            .Select(_ => RunWorkerAsync())).ConfigureAwait(false);
        return results;
    }

    internal static async Task<DnsResponse?> QueryAsync(string address, string owner, DnsRecordType type,
        int timeoutMs = 2000, CancellationToken cancellationToken = default, bool acceptRefused = false) {
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
            return (acceptRefused ? IsUsableResponse(response, acceptRefused: true) : IsAuthoritativeResponse(response)) ? response : null;
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
