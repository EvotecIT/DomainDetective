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

    private async Task<DnsAnswer[]> QueryDiscoveryAsync(QueryRun run, string owner, DnsRecordType type, InternalLogger logger, params DnsblIpSource[] sources) {
        run.CallerToken.ThrowIfCancellationRequested();
        var remaining = AnalysisTimeout - run.Budget.Elapsed;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        try {
            if (remaining <= TimeSpan.Zero) { throw new TimeoutException("Analysis budget exhausted."); }
            deadline.CancelAfter(remaining);
            var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { owner }, type, cancellationToken: deadline.Token)
                .WaitWithCancellation(deadline.Token).ConfigureAwait(false);
            var response = responses.FirstOrDefault();
            if (response == null || !string.IsNullOrEmpty(response.Error) ||
                response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                throw new InvalidOperationException(response?.Error ?? $"DNS discovery response: {response?.Status.ToString() ?? "missing"}.");
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

    private async Task<(List<DnsAnswer> Answers, string? Error)> QueryProviderAsync(QueryRun run, string query, bool ipv6) {
        run.CallerToken.ThrowIfCancellationRequested();
        var remaining = AnalysisTimeout - run.Budget.Elapsed;
        if (remaining <= TimeSpan.Zero) { return (new List<DnsAnswer>(), "Analysis budget exhausted."); }
        await _queryGate.WaitAsync(run.CallerToken).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        var answers = new List<DnsAnswer>();
        try {
            remaining = AnalysisTimeout - run.Budget.Elapsed;
            if (remaining <= TimeSpan.Zero) { return (answers, "Analysis budget exhausted."); }
            deadline.CancelAfter(ProviderTimeout == Timeout.InfiniteTimeSpan || ProviderTimeout > remaining ? remaining : ProviderTimeout);
            async Task<(DnsAnswer[] Answers, string? Error)> QueryTypeAsync(DnsRecordType type) {
                try {
                    var responseTask = QueryDnsFullOverride != null
                        ? QueryDnsFullOverride(new[] { query }, type)
                        : DnsConfiguration.QueryFullDNS(new[] { query }, type, cancellationToken: deadline.Token);
                    var response = (await responseTask.WaitWithCancellation(deadline.Token).ConfigureAwait(false)).FirstOrDefault();
                    if (response == null || !string.IsNullOrEmpty(response.Error) ||
                        response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                        return (Array.Empty<DnsAnswer>(), response?.Error ?? $"DNS response: {response?.Status.ToString() ?? "missing"}.");
                    }
                    return ((response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type).ToArray(), null);
                } catch (Exception ex) when (ex is not OutOfMemoryException) {
                    run.CallerToken.ThrowIfCancellationRequested();
                    return (Array.Empty<DnsAnswer>(), ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message);
                }
            }
            var responses = await Task.WhenAll((ipv6 ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : new[] { DnsRecordType.A }).Select(QueryTypeAsync)).ConfigureAwait(false);
            run.CallerToken.ThrowIfCancellationRequested();
            foreach (var response in responses) { answers.AddRange(response.Answers); }
            var errors = responses.Where(response => response.Error != null).Select(response => response.Error).ToArray();
            return (answers, errors.Length == 0 ? null : string.Join("; ", errors));
        } catch (OperationCanceledException) when (run.CallerToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException || ex is SocketException || ex is InvalidOperationException || ex is UriFormatException) {
            return (answers, ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message);
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
            var response = responses[i];
            foreach (var answer in response.Answers.Count == 0 ? new DnsAnswer?[] { null } : response.Answers.Cast<DnsAnswer?>()) {
                string? decoded = answer?.Data;
                string value = string.IsNullOrWhiteSpace(decoded) ? answer?.DataRaw ?? string.Empty : decoded!;
                var meaning = GetReplyCodeMeaning(zones[i], value);
                var error = value.StartsWith("127.255.", StringComparison.Ordinal) ? $"Provider returned error response {value}." : response.Error;
                yield return new DNSBLRecord {
                    Query = name, IpAddress = isIp ? ipAddressOrHostname : null, IpSource = ipSource, SourceHost = sourceHost,
                    QueryKind = kind, FQDN = $"{name}.{zones[i]}", BlackList = zones[i], Answer = value,
                    QuerySucceeded = error == null, Error = error,
                    IsBlackListed = answer != null && meaning.IsListed, ReplyMeaning = meaning.Meaning
                };
            }
        }
    }
}
