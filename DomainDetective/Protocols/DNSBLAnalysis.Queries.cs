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
    private readonly Stopwatch _queryBudget = Stopwatch.StartNew();
    private readonly SemaphoreSlim _queryGate = new(16);
    private CancellationToken _callerToken;
    /// <summary>Whether MX and address discovery completed without query failures.</summary>
    public bool DiscoverySucceeded { get; private set; } = true;
    /// <summary>Failures that prevented discovering every intended DNSBL target.</summary>
    public List<string> DiscoveryErrors { get; } = new();

    internal void BeginQueryRun(CancellationToken caller, bool clearCoverage = false) {
        _queryBudget.Restart();
        _callerToken = caller;
        if (clearCoverage) {
            DiscoverySucceeded = true;
            DiscoveryErrors.Clear();
        }
    }

    private async Task<DnsAnswer[]> QueryDiscoveryAsync(string owner, DnsRecordType type) {
        _callerToken.ThrowIfCancellationRequested();
        var remaining = AnalysisTimeout - _queryBudget.Elapsed;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_callerToken);
        try {
            if (remaining <= TimeSpan.Zero) { throw new TimeoutException("Analysis budget exhausted."); }
            deadline.CancelAfter(remaining);
            var responses = await DnsConfiguration.QueryFullDNSOrdered(new[] { owner }, type, cancellationToken: deadline.Token)
                .WaitWithCancellation(deadline.Token).ConfigureAwait(false);
            var response = responses[0];
            if (response == null || !string.IsNullOrEmpty(response.Error) ||
                response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                throw new InvalidOperationException(response?.Error ?? $"DNS discovery response: {response?.Status.ToString() ?? "missing"}.");
            }
            return response.Answers ?? Array.Empty<DnsAnswer>();
        } catch (OperationCanceledException) when (_callerToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException || ex is SocketException || ex is InvalidOperationException) {
            DiscoverySucceeded = false;
            var message = $"{owner} {type}: {ex.Message}";
            DiscoveryErrors.Add(message);
            using var collector = Logger != null ? AssessmentCollector.ForAnalysis(Logger, this, category: "DNSBL", target: owner) : null;
            Logger?.WriteWarningCode(DnsblCodes.QueryFailed, "DNSBL target discovery was incomplete: {0}", message);
            return Array.Empty<DnsAnswer>();
        }
    }

    /// <summary>Maximum duration of one provider query, including all address record types.</summary>
    public TimeSpan ProviderTimeout { get; set; } = TimeSpan.FromSeconds(2);
    /// <summary>Total provider-query budget for one analysis run. Exhaustion retains incomplete records.</summary>
    public TimeSpan AnalysisTimeout { get; set; } = TimeSpan.FromSeconds(8);

    private async Task<(List<DnsAnswer> Answers, string? Error)> QueryProviderAsync(string query, bool ipv6) {
        _callerToken.ThrowIfCancellationRequested();
        var remaining = AnalysisTimeout - _queryBudget.Elapsed;
        if (remaining <= TimeSpan.Zero) { return (new List<DnsAnswer>(), "Analysis budget exhausted."); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(_callerToken);
        deadline.CancelAfter(remaining);
        bool entered = false;
        var answers = new List<DnsAnswer>();
        try {
            await _queryGate.WaitAsync(deadline.Token).ConfigureAwait(false);
            entered = true;
            remaining = AnalysisTimeout - _queryBudget.Elapsed;
            if (remaining <= TimeSpan.Zero) { return (answers, "Analysis budget exhausted."); }
            deadline.CancelAfter(ProviderTimeout < remaining ? ProviderTimeout : remaining);
            string? error = null;
            foreach (var type in ipv6 ? new[] { DnsRecordType.A, DnsRecordType.AAAA } : new[] { DnsRecordType.A }) {
                try {
                    var responseTask = QueryDnsFullOverride != null
                        ? QueryDnsFullOverride(new[] { query }, type)
                        : DnsConfiguration.QueryFullDNS(new[] { query }, type, cancellationToken: deadline.Token);
                    var response = (await responseTask.WaitWithCancellation(deadline.Token).ConfigureAwait(false)).FirstOrDefault();
                    if (response == null || !string.IsNullOrEmpty(response.Error) ||
                        response.Status != DnsResponseCode.NoError && response.Status != DnsResponseCode.NXDomain) {
                        error = response?.Error ?? $"DNS response: {response?.Status.ToString() ?? "missing"}.";
                        continue;
                    }
                    answers.AddRange((response.Answers ?? Array.Empty<DnsAnswer>()).Where(answer => answer.Type == type));
                } catch (Exception ex) when (!_callerToken.IsCancellationRequested &&
                    (ex is OperationCanceledException || ex is TimeoutException || ex is SocketException || ex is InvalidOperationException || ex is UriFormatException)) {
                    error = ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message;
                }
            }
            return (answers, error);
        } catch (OperationCanceledException) when (_callerToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is OperationCanceledException || ex is TimeoutException || ex is SocketException || ex is InvalidOperationException || ex is UriFormatException) {
            return (answers, ex is OperationCanceledException ? "Provider query timed out or analysis budget exhausted." : ex.Message);
        } finally {
            if (entered) { _queryGate.Release(); }
        }
    }

    private async IAsyncEnumerable<DNSBLRecord> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname, DnsblIpSource? ipSource = null, string? sourceHost = null) {
        if (dnsblList == null) { yield break; }
        var zones = dnsblList.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        bool isIp = IPAddress.TryParse(ipAddressOrHostname, out var address);
        bool ipv6 = isIp && address!.AddressFamily == AddressFamily.InterNetworkV6;
        var kind = isIp ? (ipv6 ? DnsblQueryKind.IpAddressV6 : DnsblQueryKind.IpAddressV4) : DnsblQueryKind.Domain;
        var name = isIp ? FormatDnsblName(address!) : ipAddressOrHostname;
        var responses = await Task.WhenAll(zones.Select(zone => QueryProviderAsync($"{name}.{zone}", ipv6))).ConfigureAwait(false);
        for (int i = 0; i < zones.Length; i++) {
            _callerToken.ThrowIfCancellationRequested();
            var response = responses[i];
            foreach (var answer in response.Answers.Count == 0 ? new DnsAnswer?[] { null } : response.Answers.Cast<DnsAnswer?>()) {
                string value = answer?.Data ?? answer?.DataRaw ?? string.Empty;
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
