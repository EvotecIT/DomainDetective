using DnsClientX;
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DNSBLAnalysis {
    // A single analysis also supports concurrent append runs. Keep their aggregate
    // provider admission bounded while each run retains its own budget and cap.
    private readonly SemaphoreSlim _providerAdmission = new(32);
    internal sealed class QueryRun : IDisposable {
        internal CancellationToken CallerToken { get; }
        internal Stopwatch Budget { get; } = Stopwatch.StartNew();
        internal SemaphoreSlim ProviderGate { get; }
        internal int MaxParallelism { get; }
        internal ConcurrentDictionary<string, string> BlockedProviders { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal QueryRun(CancellationToken callerToken, int maxParallelism) {
            CallerToken = callerToken;
            MaxParallelism = maxParallelism;
            ProviderGate = new SemaphoreSlim(maxParallelism);
        }
        public void Dispose() => ProviderGate.Dispose();
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

    internal QueryRun BeginQueryRun(CancellationToken caller) {
        int parallelism = Math.Min(DnsConfiguration.ResolverMaxConcurrency ?? 16, DnsConfiguration.GetReusableQueryParallelism());
        return new(caller, Math.Min(32, Math.Max(1, parallelism)));
    }

    private async Task<DnsAnswer[]> QueryDiscoveryAsync(QueryRun run, string owner, DnsRecordType type, InternalLogger? logger, params DnsblIpSource[] sources) {
        run.CallerToken.ThrowIfCancellationRequested();
        if (DiscoveryTimeout <= TimeSpan.Zero && DiscoveryTimeout != Timeout.InfiniteTimeSpan) {
            throw new ArgumentOutOfRangeException(nameof(DiscoveryTimeout));
        }
        var remaining = RemainingBudget(run);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        try {
            if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { throw new TimeoutException("Analysis budget exhausted."); }
            // With one resolver slot, leave time for already-resolved targets instead
            // of allowing a slow family to occupy that slot for the entire run.
            var discoveryBudget = run.MaxParallelism == 1 && remaining.HasValue
                ? TimeSpan.FromTicks(Math.Max(1, remaining.Value.Ticks / 2)) : remaining;
            TimeSpan? timeout = DiscoveryTimeout == Timeout.InfiniteTimeSpan ? discoveryBudget :
                discoveryBudget.HasValue && discoveryBudget.Value < DiscoveryTimeout ? discoveryBudget : DiscoveryTimeout;
            if (timeout.HasValue) { deadline.CancelAfter(timeout.Value); }
            var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { owner }, type, cancellationToken: deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            var response = responses.FirstOrDefault();
            if (response == null || !string.IsNullOrEmpty(response.Error) ||
                response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                throw new InvalidOperationException(ResponseFailure(response));
            }
            var answers = (response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type).ToArray();
            if (type == DnsRecordType.A || type == DnsRecordType.AAAA) {
                var family = type == DnsRecordType.A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                if (answers.Any(answer => !IPAddress.TryParse(answer.Data, out var ip) || ip.AddressFamily != family)) {
                    throw new FormatException($"DNS {type} discovery returned an invalid address.");
                }
            }
            return answers;
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
    /// <summary>Timeout for one MX or address discovery lookup, including recursive-query admission. Exhaustion retains incomplete target coverage.</summary>
    public TimeSpan DiscoveryTimeout { get; set; } = TimeSpan.FromSeconds(2);

    private TimeSpan? RemainingBudget(QueryRun run) => AnalysisTimeout == Timeout.InfiniteTimeSpan ? null : AnalysisTimeout - run.Budget.Elapsed;

    private static string ResponseFailure(DnsResponse? response) => !string.IsNullOrEmpty(response?.Error)
        ? response!.Error : $"DNS response: {response?.Status.ToString() ?? "missing"}.";

    private async Task<(DnsRecordType Type, DnsAnswer[] Answers, string? Error)[]> QueryProviderAsync(QueryRun run, string query, bool ipv6, string zone) {
        run.CallerToken.ThrowIfCancellationRequested();
        var types = ipv6 && !UsesSpamhausAResponses(zone) ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : new[] { DnsRecordType.A };
        (DnsRecordType Type, DnsAnswer[] Answers, string? Error)[] Failed(string error) =>
            types.Select(type => (type, Array.Empty<DnsAnswer>(), (string?)error)).ToArray();
        if (run.BlockedProviders.TryGetValue(zone, out var blocked)) { return Failed(blocked); }
        var remaining = RemainingBudget(run);
        if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { return Failed("Analysis budget exhausted."); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(run.CallerToken);
        bool runAdmitted = false;
        bool analysisAdmitted = false;
        try {
            if (remaining.HasValue) { deadline.CancelAfter(remaining.Value); }
            await run.ProviderGate.WaitAsync(deadline.Token).ConfigureAwait(false);
            runAdmitted = true;
            await _providerAdmission.WaitAsync(deadline.Token).ConfigureAwait(false);
            analysisAdmitted = true;
            if (run.BlockedProviders.TryGetValue(zone, out blocked)) { return Failed(blocked); }
            remaining = RemainingBudget(run);
            if (remaining.HasValue && remaining.Value <= TimeSpan.Zero) { return Failed("Analysis budget exhausted."); }
            TimeSpan? timeout = ProviderTimeout == Timeout.InfiniteTimeSpan ? remaining :
                remaining.HasValue && remaining.Value < ProviderTimeout ? remaining : ProviderTimeout;
            using var executionDeadline = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            int executionStarted = 0;
            void StartExecution() {
                if (Interlocked.CompareExchange(ref executionStarted, 1, 0) == 0 && timeout.HasValue) {
                    executionDeadline.CancelAfter(timeout.Value);
                }
            }
            async Task<(DnsRecordType Type, DnsAnswer[] Answers, string? Error)> QueryTypeAsync(DnsRecordType type) {
                try {
                    if (QueryDnsFullOverride != null) { StartExecution(); }
                    var response = QueryDnsFullOverride != null
                        ? (await QueryDnsFullOverride(new[] { query }, type).WaitWithCancellation(executionDeadline.Token).ConfigureAwait(false)).FirstOrDefault()
                        : await DnsConfiguration.QueryDNSResponseAfterAdmission(query, type, executionDeadline.Token, StartExecution).ConfigureAwait(false);
                    executionDeadline.Token.ThrowIfCancellationRequested();
                    if (response == null || !string.IsNullOrEmpty(response.Error) ||
                        response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                        return (type, Array.Empty<DnsAnswer>(), ResponseFailure(response));
                    }
                    var answers = (response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type).ToArray();
                    // This is a conclusive access-policy reply, not a timeout or a
                    // target listing. Keep every subsequent target explicitly unknown.
                    if (CanShareProviderAccessFailure() && UsesSpamhausAResponses(zone) && answers.Any(answer =>
                        (string.IsNullOrWhiteSpace(answer.Data) ? answer.DataRaw : answer.Data) == "127.255.255.254")) {
                        run.BlockedProviders.TryAdd(zone, "Provider access blocked by the selected public resolver (127.255.255.254).");
                    }
                    return (type, answers, null);
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
            if (analysisAdmitted) { _providerAdmission.Release(); }
            if (runAdmitted) { run.ProviderGate.Release(); }
        }
    }

    private bool CanShareProviderAccessFailure() {
        var providers = DnsConfiguration.DnsEndpoints.Count > 0
            ? DnsConfiguration.DnsEndpoints.ToArray() : new[] { DnsConfiguration.DnsEndpoint };
        // One blocked recursive path says nothing about a different resolver.
        // Cloudflare's address/transport variants belong to the same public
        // resolver service covered by Spamhaus's public-resolver access policy.
        return providers.Distinct().Count() == 1 &&
            (providers[0] == DnsEndpoint.Cloudflare || providers[0] == DnsEndpoint.CloudflareWireFormat)
            || DnsResolverEndpointFactory.From(providers).Length == 1;
    }

    // Spamhaus documents A-record result codes for both input address families:
    // https://docs.spamhaus.com/datasets/docs/source/10-data-type-documentation/datasets/040-zones.html
    // Unknown/custom zones retain the historical A+AAAA IPv6 response plan.
    private static bool UsesSpamhausAResponses(string zone) => zone.TrimEnd('.').ToLowerInvariant() is
        "zen.spamhaus.org" or "sbl.spamhaus.org" or "xbl.spamhaus.org" or "pbl.spamhaus.org" or
        "dbl.spamhaus.org" or "hbl.spamhaus.org" || zone.EndsWith(".dq.spamhaus.net", StringComparison.OrdinalIgnoreCase);

    private async IAsyncEnumerable<DNSBLRecord> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname, QueryRun run, DnsblIpSource? ipSource = null, string? sourceHost = null) {
        if (dnsblList == null) { yield break; }
        var zones = dnsblList.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        bool isIp = IPAddress.TryParse(ipAddressOrHostname, out var address);
        bool ipv6 = isIp && address!.AddressFamily == AddressFamily.InterNetworkV6;
        var kind = isIp ? (ipv6 ? DnsblQueryKind.IpAddressV6 : DnsblQueryKind.IpAddressV4) : DnsblQueryKind.Domain;
        var name = isIp ? FormatDnsblName(address!) : ipAddressOrHostname;
        var responses = await Helpers.BoundedAsync.RunAsync(zones, zone => QueryProviderAsync(run, $"{name}.{zone}", ipv6, zone), run.MaxParallelism, run.CallerToken).ConfigureAwait(false);
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
            if (responses[i].All(response => response.Error == null && response.Answers.Length == 0)) {
                yield return Record(string.Empty, null, false);
            }
        }
    }
}
