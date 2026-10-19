using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class MXAnalysis {
    /// <summary>Optional fixed authoritative answer source; null means the TTL evidence is unavailable.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]?>>? AuthoritativeQueryOverride { private get; set; }
    /// <summary>Whether the MX TTL values came from an authoritative response or fixed replay.</summary>
    public bool TtlsFromAuthoritativeServers { get; private set; }
    private readonly Dictionary<string, DnsAnswer[]> _authoritativeTtlAnswers = new(StringComparer.OrdinalIgnoreCase);
    private static string TtlAnswerKey(string owner, DnsRecordType type) => owner.TrimEnd('.') + "|" + type;

    private async Task EvaluateAuthoritativeTtlsAsync(IReadOnlyList<DnsAnswer> mxRecords,
        IEnumerable<(string Host, DnsAnswer[]? A, DnsAnswer[]? Aaaa)> hostResults, InternalLogger logger,
        AssessmentCollector collector, CancellationToken token) {
        var hosts = hostResults.ToArray();
        var requests = new List<(string Owner, DnsRecordType Type)> { (Subject ?? string.Empty, DnsRecordType.MX) };
        requests.AddRange(hosts.SelectMany(host => new[] { (host.Host, DnsRecordType.A), (host.Host, DnsRecordType.AAAA) }));
        if (AuthoritativeQueryOverride != null) {
            var responses = await Helpers.AuthoritativeDnsProbes.RunAsync(requests, async request =>
                (request.Owner, request.Type, Answers: await AuthoritativeQueryOverride(request.Owner, request.Type).ConfigureAwait(false)),
                concurrency: Math.Max(1, Math.Min(8, DnsConfiguration.ResolverMaxConcurrency ?? 8)), cancellationToken: token).ConfigureAwait(false);
            foreach (var response in responses) {
                if (response.Answers != null) { _authoritativeTtlAnswers[TtlAnswerKey(response.Owner, response.Type)] = response.Answers.Where(answer => answer.Type == response.Type).ToArray(); }
            }
        } else if (QueryDnsOverride != null || DnsConfiguration.QueryDnsOverride != null) {
            _authoritativeTtlAnswers[TtlAnswerKey(Subject ?? string.Empty, DnsRecordType.MX)] = mxRecords.ToArray();
            foreach (var host in hosts) {
                if (host.A != null) { _authoritativeTtlAnswers[TtlAnswerKey(host.Host, DnsRecordType.A)] = host.A; }
                if (host.Aaaa != null) { _authoritativeTtlAnswers[TtlAnswerKey(host.Host, DnsRecordType.AAAA)] = host.Aaaa; }
            }
        }
        if (_authoritativeTtlAnswers.TryGetValue(TtlAnswerKey(Subject ?? string.Empty, DnsRecordType.MX), out var mx) && mx.Length > 0) {
            TtlsFromAuthoritativeServers = true;
            var ttls = mx.Select(answer => answer.TTL).ToArray();
            MxRecordTtls = ttls;
            var positive = ttls.Where(ttl => ttl > 0).ToArray();
            MinMxTtl = positive.Length > 0 ? positive.Min() : null;
            MaxMxTtl = positive.Length > 0 ? positive.Max() : null;
            AvgMxTtl = positive.Length > 0 ? positive.Average() : null;
            if (ttls.Distinct().Skip(1).Any()) {
                MxTtlUniform = false;
                using (collector.PushTarget(Subject ?? string.Empty)) { logger.WriteWarningCode(MxCodes.TtlNonUniform, "MX RRset TTLs differ across records"); }
            }
        }
        foreach (var host in hosts) {
            if (!_authoritativeTtlAnswers.TryGetValue(TtlAnswerKey(host.Host, DnsRecordType.A), out var a)
                || !_authoritativeTtlAnswers.TryGetValue(TtlAnswerKey(host.Host, DnsRecordType.AAAA), out var aaaa)) { continue; }
            if (a.Concat(aaaa).Select(answer => answer.TTL).Distinct().Skip(1).Any()) {
                using (collector.PushTarget(host.Host)) { logger.WriteWarningCode(MxCodes.TargetTtlNonUniform, "A/AAAA TTLs differ for MX host"); }
            }
        }
    }
}
