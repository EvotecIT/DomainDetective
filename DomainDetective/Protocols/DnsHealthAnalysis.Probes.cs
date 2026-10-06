using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DnsHealthAnalysis {
    private async Task<DnsHealthDiscoveryResult> DiscoverAsync(string name, DnsRecordType type,
        CancellationToken budget, CancellationToken caller) {
        var result = new DnsHealthDiscoveryResult { Name = name, RecordType = type };
        try {
            budget.ThrowIfCancellationRequested();
            var response = await DnsConfiguration.QueryDNSResponse(name, type, cancellationToken: budget).ConfigureAwait(false);
            caller.ThrowIfCancellationRequested();
            result.ResponseCode = response.Status;
            result.Error = response.Error;
            if (result.Succeeded) result.Answers = response.Answers.Where(answer => answer.Type == type).ToArray();
        } catch (Exception ex) when (!caller.IsCancellationRequested && !ExceptionHelper.IsFatal(ex)) {
            result.Error = budget.IsCancellationRequested ? "Analysis budget exhausted during discovery." : ex.Message;
        }
        caller.ThrowIfCancellationRequested();
        return result;
    }

    private async Task<DnsHealthProbeResult> ProbeAsync(IPAddress server, List<string> owners, string zone,
        DnsRecordType type, int timeout, CancellationToken budget, CancellationToken caller) {
        var result = new DnsHealthProbeResult { ServerAddress = server.ToString(), NameServers = owners.ToArray(), RecordType = type };
        var elapsed = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(budget);
        deadline.CancelAfter(timeout);
        try {
            deadline.Token.ThrowIfCancellationRequested();
            var query = new DnsMessage(zone, type, new DnsMessageOptions(RecursionDesired: false));
            result.Attempted = true;
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
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex)) { result.Error = ex.Message; }
        finally { result.ElapsedMilliseconds = elapsed.ElapsedMilliseconds; }
        return result;
    }

}
