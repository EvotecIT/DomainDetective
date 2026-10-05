using DnsClientX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DnsHealthAnalysis {
    private async Task<DnsHealthProbeResult> ProbeAsync(IPAddress server, List<string> owners, string zone,
        DnsRecordType type, int timeout, CancellationToken budget, CancellationToken caller) {
        var result = new DnsHealthProbeResult { ServerAddress = server.ToString(), NameServers = owners.ToArray(), RecordType = type };
        var elapsed = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(budget);
        deadline.CancelAfter(timeout);
        try {
            deadline.Token.ThrowIfCancellationRequested();
            var query = new DnsMessage(zone, type, new DnsMessageOptions(RecursionDesired: false));
            DnsResponse? response = QueryResponseOverride != null
                ? await QueryResponseOverride(server, query, deadline.Token).ConfigureAwait(false)
                : (await DnsWireQueryClient.QueryUdpAsync(server.ToString(), 53, query, timeout,
                    useTcpFallback: true, cancellationToken: deadline.Token).ConfigureAwait(false)).Response;
            caller.ThrowIfCancellationRequested();
            if (response != null) {
                result.ResponseCode = response.Status;
                result.IsAuthoritative = response.IsAuthoritativeAnswer;
                result.Error = response.Error;
                result.Answers = response.Answers.Where(answer => answer.Type == type
                    && string.Equals(answer.Name?.TrimEnd('.'), zone.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)).ToArray();
            } else { result.Error = "No DNS response was received."; }
        } catch (OperationCanceledException) when (caller.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { result.Error = budget.IsCancellationRequested ? "Analysis budget exhausted." : "Probe timed out."; }
        catch (Exception ex) { result.Error = ex.Message; }
        finally { result.ElapsedMilliseconds = elapsed.ElapsedMilliseconds; }
        return result;
    }

    // Fixed worker count avoids creating one waiting task for every authoritative query.
    private static async Task<T[]> RunWorkers<T>(int count, int concurrency, Func<int, Task<T>> operation) {
        var results = new T[count];
        int next = -1;
        async Task Worker() {
            while (true) {
                int index = Interlocked.Increment(ref next);
                if (index >= count) return;
                results[index] = await operation(index).ConfigureAwait(false);
            }
        }
        await Task.WhenAll(Enumerable.Range(0, Math.Min(count, concurrency)).Select(_ => Worker())).ConfigureAwait(false);
        return results;
    }
}
