using DnsClientX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DNSBLAnalysis {
    private readonly SemaphoreSlim _queryGate = new(16);
    internal sealed class QueryRun {
        internal CancellationToken CallerToken { get; }
        internal Stopwatch Budget { get; } = Stopwatch.StartNew();
        internal QueryRun(CancellationToken callerToken) { CallerToken = callerToken; }
    }
    /// <summary>Whether MX and address discovery completed without query failures.</summary>
    public bool DiscoverySucceeded { get; private set; } = true;
    /// <summary>Failures that prevented discovering every intended DNSBL target.</summary>
    public List<string> DiscoveryErrors { get; } = new();
    private readonly HashSet<DnsblIpSource> _failedDiscoverySources = new();

    internal bool HasDiscoveryFailure(ISet<DnsblIpSource>? sources, ISet<DnsblQueryKind>? kinds) {
        lock (SyncRoot) {
            return _failedDiscoverySources.Any(source => (sources == null || sources.Contains(source)) &&
                (kinds == null || kinds.Contains(source == DnsblIpSource.MxAAAA || source == DnsblIpSource.ApexAAAA
                    ? DnsblQueryKind.IpAddressV6 : DnsblQueryKind.IpAddressV4)));
        }
    }

    internal QueryRun BeginQueryRun(CancellationToken caller) => new(caller);

    private async Task<DnsAnswer[]> QueryDiscoveryAsync(QueryRun run, string owner, DnsRecordType type, InternalLogger? logger, params DnsblIpSource[] sources) {
        run.CallerToken.ThrowIfCancellationRequested();
        var remaining = RemainingBudget(run);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        try {
            if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { throw new TimeoutException("Analysis budget exhausted."); }
            if (remaining.HasValue) { deadline.CancelAfter(remaining.Value); }
            var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { owner }, type, cancellationToken: deadline.Token)
                .WaitWithCancellation(deadline.Token).ConfigureAwait(false);
            var response = responses.FirstOrDefault();
            if (response == null || !string.IsNullOrEmpty(response.Error) ||
                response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                throw new InvalidOperationException(ResponseFailure(response));
            }
            return response.Answers ?? Array.Empty<DnsAnswer>();
        } catch (OperationCanceledException) when (run.CallerToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is not OutOfMemoryException) {
            run.CallerToken.ThrowIfCancellationRequested();
            var message = $"{owner} {type}: {ex.Message}";
            var warning = $"DNSBL target discovery was incomplete: {message}";
            lock (SyncRoot) {
                DiscoverySucceeded = false;
                foreach (var source in sources) { _failedDiscoverySources.Add(source); }
                DiscoveryErrors.Add(message);
                using var collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSBL", target: owner) : null;
                collector?.AddWarning(warning, DnsblCodes.QueryFailed);
            }
            logger?.WriteWarningCode(DnsblCodes.QueryFailed, warning);
            return Array.Empty<DnsAnswer>();
        }
    }

    /// <summary>Maximum duration of one provider query, including all address record types.</summary>
    public TimeSpan ProviderTimeout { get; set; } = TimeSpan.FromSeconds(2);
    /// <summary>Total provider-query budget for one analysis run. Exhaustion retains incomplete records.</summary>
    public TimeSpan AnalysisTimeout { get; set; } = TimeSpan.FromSeconds(8);

    private TimeSpan? RemainingBudget(QueryRun run) => AnalysisTimeout == Timeout.InfiniteTimeSpan ? null : AnalysisTimeout - run.Budget.Elapsed;

    private static string ResponseFailure(DnsResponse? response) => !string.IsNullOrEmpty(response?.Error)
        ? response!.Error : $"DNS response: {response?.Status.ToString() ?? "missing"}.";

    private async Task<(DnsRecordType Type, DnsAnswer[] Answers, string? Error)[]> QueryProviderAsync(QueryRun run, string query, bool ipv6) {
        run.CallerToken.ThrowIfCancellationRequested();
        var types = ipv6 ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : new[] { DnsRecordType.A };
        (DnsRecordType Type, DnsAnswer[] Answers, string? Error)[] Failed(string error) =>
            types.Select(type => (type, Array.Empty<DnsAnswer>(), (string?)error)).ToArray();
        var remaining = RemainingBudget(run);
        if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { return Failed("Analysis budget exhausted."); }
        await _queryGate.WaitAsync(run.CallerToken).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        try {
            remaining = RemainingBudget(run);
            if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { return Failed("Analysis budget exhausted."); }
            TimeSpan? timeout = ProviderTimeout == Timeout.InfiniteTimeSpan ? remaining :
                remaining.HasValue && remaining.Value < ProviderTimeout ? remaining : ProviderTimeout;
            if (timeout.HasValue) { deadline.CancelAfter(timeout.Value); }
            async Task<(DnsRecordType Type, DnsAnswer[] Answers, string? Error)> QueryTypeAsync(DnsRecordType type) {
                try {
                    var responseTask = QueryDnsFullOverride != null
                        ? QueryDnsFullOverride(new[] { query }, type)
                        : DnsConfiguration.QueryFullDNS(new[] { query }, type, cancellationToken: deadline.Token);
                    var response = (await responseTask.WaitWithCancellation(deadline.Token).ConfigureAwait(false)).FirstOrDefault();
                    if (response == null || !string.IsNullOrEmpty(response.Error) ||
                        response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                        return (type, Array.Empty<DnsAnswer>(), ResponseFailure(response));
                    }
                    return (type, (response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type).ToArray(), null);
                } catch (Exception ex) when (ex is not OutOfMemoryException) {
                    run.CallerToken.ThrowIfCancellationRequested();
                    return (type, Array.Empty<DnsAnswer>(), ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message);
                }
            }
            var responses = await Task.WhenAll(types.Select(QueryTypeAsync)).ConfigureAwait(false);
            run.CallerToken.ThrowIfCancellationRequested();
            return responses;
        } catch (OperationCanceledException) when (run.CallerToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException || ex is SocketException || ex is InvalidOperationException || ex is UriFormatException) {
            return Failed(ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message);
        } finally {
            _queryGate.Release();
        }
    }

    private async IAsyncEnumerable<DNSBLRecord> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname, QueryRun run, DnsblIpSource? ipSource = null, string? sourceHost = null) {
        if (dnsblList == null) { yield break; }
        var zones = dnsblList.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        bool isIp = IPAddress.TryParse(ipAddressOrHostname, out var address);
        bool ipv6 = isIp && address!.AddressFamily == AddressFamily.InterNetworkV6;
        var kind = isIp ? (ipv6 ? DnsblQueryKind.IpAddressV6 : DnsblQueryKind.IpAddressV4) : DnsblQueryKind.Domain;
        var name = isIp ? FormatDnsblName(address!) : ipAddressOrHostname;
        var responses = await Helpers.BoundedAsync.RunAsync(zones, zone => QueryProviderAsync(run, $"{name}.{zone}", ipv6), 16, run.CallerToken).ConfigureAwait(false);
        for (int i = 0; i < zones.Length; i++) {
            run.CallerToken.ThrowIfCancellationRequested();
            DNSBLRecord Record(string value, string? error, bool hasAnswer) {
                var meaning = GetReplyCodeMeaning(zones[i], value);
                return new DNSBLRecord {
                    Query = name, IpAddress = isIp ? ipAddressOrHostname : null, IpSource = ipSource, SourceHost = sourceHost,
                    QueryKind = kind, FQDN = $"{name}.{zones[i]}", BlackList = zones[i], Answer = value,
                    QuerySucceeded = error == null, Error = error,
                    IsBlackListed = hasAnswer && meaning.IsListed, ReplyMeaning = meaning.Meaning
                };
            }
            foreach (var response in responses[i]) {
                if (response.Error != null) {
                    yield return Record(string.Empty, $"{response.Type}: {response.Error}", false);
                    continue;
                }
                if (response.Answers.Length == 0) { yield return Record(string.Empty, null, false); }
                var reserved = new HashSet<string>(StringComparer.Ordinal);
                foreach (var answer in response.Answers) {
                    var value = string.IsNullOrWhiteSpace(answer.Data) ? answer.DataRaw ?? string.Empty : answer.Data;
                    if (value.StartsWith("127.255.", StringComparison.Ordinal)) { reserved.Add(value); }
                    else { yield return Record(value, null, true); }
                }
                if (reserved.Count > 0) {
                    yield return Record(reserved.First(), $"{response.Type}: Provider returned error response {string.Join(", ", reserved)}.", false);
                }
            }
        }
    }
}
