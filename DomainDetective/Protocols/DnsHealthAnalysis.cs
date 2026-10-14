using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>Compares authoritative SOA and apex records with bounded probes and explicit coverage.</summary>
public partial class DnsHealthAnalysis : IHasAssessments {
    /// <summary>Gets or sets the analyzed domain.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the resolver used for nameserver discovery.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();
    /// <summary>Optional parsed-response override for direct authoritative probes.</summary>
    public Func<IPAddress, DnsMessage, CancellationToken, Task<DnsResponse?>>? QueryResponseOverride { get; set; }
    /// <summary>Maximum concurrent discovery or authoritative queries. Values below one use one worker.</summary>
    public int QueryConcurrency { get; set; } = 6;
    /// <summary>Deadline for one authoritative probe, including UDP-to-TCP fallback.</summary>
    public int QueryTimeoutMilliseconds { get; set; } = 4000;
    /// <summary>Total discovery and probing budget. Expiration retains incomplete coverage.</summary>
    public int AnalysisTimeoutMilliseconds { get; set; } = 15000;
    /// <summary>Gets the discovered nameserver hostnames.</summary>
    public List<string> NameServers { get; } = new();
    /// <summary>Gets nameservers for which no address was discovered.</summary>
    public List<string> UnresolvedNameServers { get; } = new();
    /// <summary>Gets every NS/A/AAAA discovery result, retaining errors and successful NODATA.</summary>
    public List<DnsHealthDiscoveryResult> DiscoveryResults { get; } = new();
    /// <summary>True when NS and both address families completed successfully for every nameserver.</summary>
    public bool DiscoveryComplete { get; private set; }
    /// <summary>Gets the number of distinct authoritative addresses targeted.</summary>
    public int ExpectedServerCount { get; private set; }
    /// <summary>Gets every planned probe, including unanswered and budget-exhausted probes.</summary>
    public List<DnsHealthProbeResult> ProbeResults { get; } = new();
    /// <summary>Gets authoritative SOA serials by address.</summary>
    public Dictionary<string, long> SoaSerialByServer { get; } = new();
    /// <summary>Gets the SOA comparison conclusion.</summary>
    public DnsHealthConsistencyStatus SoaSerialConsistency { get; private set; }
    /// <summary>True only when at least two endpoints agree with complete SOA coverage.</summary>
    public bool SoaSerialConsistent => SoaSerialConsistency == DnsHealthConsistencyStatus.Consistent;
    /// <summary>Gets apex A/AAAA sets from endpoints with both successful authoritative responses, including NODATA.</summary>
    public Dictionary<string, List<string>> ApexAddressesByServer { get; } = new();
    /// <summary>Gets the apex comparison conclusion.</summary>
    public DnsHealthConsistencyStatus ApexAddressesConsistency { get; private set; }
    /// <summary>True only when at least two endpoints agree with complete apex coverage.</summary>
    public bool ApexAddressesConsistent => ApexAddressesConsistency == DnsHealthConsistencyStatus.Consistent;
    /// <summary>True when discovery is complete and every discovered address replied to every probe.</summary>
    public bool ServersResponsive { get; private set; }
    /// <summary>Gets the per-run assessments.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Analyzes authoritative consistency and responsiveness without multiplying timeout budgets.</summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
        if (QueryTimeoutMilliseconds <= 0) throw new ArgumentOutOfRangeException(nameof(QueryTimeoutMilliseconds));
        if (AnalysisTimeoutMilliseconds <= 0) throw new ArgumentOutOfRangeException(nameof(AnalysisTimeoutMilliseconds));
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSHEALTH", target: domainName);
        Subject = domainName;
        NameServers.Clear(); UnresolvedNameServers.Clear(); ProbeResults.Clear(); DiscoveryResults.Clear();
        SoaSerialByServer.Clear(); ApexAddressesByServer.Clear(); Assessments.Clear();
        ExpectedServerCount = 0; ServersResponsive = false; DiscoveryComplete = false;
        SoaSerialConsistency = ApexAddressesConsistency = DnsHealthConsistencyStatus.InsufficientEvidence;
        int concurrency = Math.Max(1, QueryConcurrency);
        int queryTimeout = QueryTimeoutMilliseconds;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(AnalysisTimeoutMilliseconds);

        var nameservers = await DiscoverAsync(domainName, DnsRecordType.NS, budget.Token, cancellationToken).ConfigureAwait(false);
        DiscoveryResults.Add(nameservers);
        if (!nameservers.Succeeded) {
            logger.WriteWarningCode(DnsHealthCodes.CoverageIncomplete, "Nameserver discovery did not complete; DNS health evidence is incomplete");
            return;
        }
        cancellationToken.ThrowIfCancellationRequested();
        string[] hosts = nameservers.Answers.Where(answer => answer.Type == DnsRecordType.NS)
            .Select(answer => answer.Data.TrimEnd('.')).Where(host => !string.IsNullOrWhiteSpace(host))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        NameServers.AddRange(hosts);
        var discovery = hosts.SelectMany(host => new[] { (host, DnsRecordType.A), (host, DnsRecordType.AAAA) }).ToArray();
        var addressResults = await BoundedAsyncWork.MapAsync(discovery.Length, concurrency, index =>
            DiscoverAsync(discovery[index].host, discovery[index].Item2, budget.Token, cancellationToken)).ConfigureAwait(false);
        DiscoveryResults.AddRange(addressResults);
        DiscoveryComplete = hosts.Length > 0 && addressResults.All(result => result.Succeeded);
        var servers = new Dictionary<IPAddress, List<string>>();
        for (int i = 0; i < hosts.Length; i++) {
            IPAddress[] found = addressResults[i * 2].Answers.Concat(addressResults[i * 2 + 1].Answers)
                .Select(answer => IPAddress.TryParse(answer.Data, out var ip) ? ip : null)
                .Where(ip => ip != null).Select(ip => ip!).Distinct().ToArray();
            if (found.Length == 0) UnresolvedNameServers.Add(hosts[i]);
            foreach (var ip in found) {
                if (!servers.TryGetValue(ip, out var owners)) servers[ip] = owners = new List<string>();
                owners.Add(hosts[i]);
            }
        }
        ExpectedServerCount = servers.Count;
        var probes = servers.SelectMany(server => new[] { DnsRecordType.SOA, DnsRecordType.A, DnsRecordType.AAAA }
            .Select(type => (server.Key, server.Value, type))).ToArray();
        ProbeResults.AddRange(await BoundedAsyncWork.MapAsync(probes.Length, concurrency, index =>
            ProbeAsync(probes[index].Key, probes[index].Value, domainName, probes[index].type,
                queryTimeout, budget.Token, cancellationToken)).ConfigureAwait(false));
        cancellationToken.ThrowIfCancellationRequested();
        Evaluate(logger);
    }

    private void Evaluate(InternalLogger logger) {
        foreach (var server in ProbeResults.GroupBy(probe => probe.ServerAddress)) {
            var soa = server.Single(probe => probe.RecordType == DnsRecordType.SOA);
            string? data = soa.Answers.Select(answer => answer.Data).FirstOrDefault();
            string[] parts = (data ?? string.Empty).Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (soa.ResponseSucceeded && soa.IsAuthoritative && parts.Length >= 3 && long.TryParse(parts[2], out long serial)) {
                SoaSerialByServer[server.Key] = serial;
            }
            var apex = server.Where(probe => probe.RecordType != DnsRecordType.SOA).ToArray();
            if (apex.All(probe => probe.ResponseSucceeded && probe.IsAuthoritative)) {
                ApexAddressesByServer[server.Key] = apex.SelectMany(probe => probe.Answers)
                    .Select(answer => answer.Data).Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
            }
        }
        SoaSerialConsistency = Compare(SoaSerialByServer.Count, SoaSerialByServer.Values.Select(value => value.ToString()).Distinct().Count());
        ApexAddressesConsistency = Compare(ApexAddressesByServer.Count,
            ApexAddressesByServer.Values.Select(values => string.Join(",", values)).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        if (SoaSerialConsistency == DnsHealthConsistencyStatus.Inconsistent) {
            logger.WriteWarningCode(DnsHealthCodes.SoaSerialSkew, "SOA serial numbers differ across observed authoritative servers");
        } else if (SoaSerialConsistent) {
            logger.WriteInformationCode(DnsHealthCodes.SoaSerialConsistent, "SOA serial numbers consistent across authoritative servers");
        }
        if (ApexAddressesConsistency == DnsHealthConsistencyStatus.Inconsistent) {
            logger.WriteWarningCode(DnsHealthCodes.ApexInconsistent, "A/AAAA answers for zone apex differ across observed authoritative servers");
        }
        ServersResponsive = ExpectedServerCount > 0 && DiscoveryComplete && UnresolvedNameServers.Count == 0
            && ProbeResults.All(probe => probe.HasResponse);
        if (ServersResponsive) logger.WriteInformationCode(DnsHealthCodes.ServersResponsive, "All authoritative name servers responded to queries");
        if (!ServersResponsive || !SoaSerialConsistent || !ApexAddressesConsistent) {
            if (!DiscoveryComplete || UnresolvedNameServers.Count > 0 || ProbeResults.Any(probe => !probe.HasResponse)
                || SoaSerialConsistency == DnsHealthConsistencyStatus.InsufficientEvidence
                || ApexAddressesConsistency == DnsHealthConsistencyStatus.InsufficientEvidence) {
                logger.WriteWarningCode(DnsHealthCodes.CoverageIncomplete, "DNS health coverage is incomplete; consistency cannot be confirmed for every authoritative server");
            }
        }
        foreach (var probe in ProbeResults.Where(probe => probe.HasResponse && (!probe.ResponseSucceeded || !probe.IsAuthoritative))) {
            string detail = probe.Error ?? (!probe.IsAuthoritative ? "Non-authoritative DNS response." : probe.ResponseCode!.Value.ToString());
            logger.WriteWarningCode(DnsHealthCodes.QueryFailed, $"{probe.ServerAddress} {probe.RecordType}: {detail}");
        }
    }

    private DnsHealthConsistencyStatus Compare(int observed, int distinct) => distinct > 1
        ? DnsHealthConsistencyStatus.Inconsistent
        : observed >= 2 && observed == ExpectedServerCount && DiscoveryComplete && UnresolvedNameServers.Count == 0
            ? DnsHealthConsistencyStatus.Consistent : DnsHealthConsistencyStatus.InsufficientEvidence;

    internal string ResponsivenessSummary => ServersResponsive ? "All authoritative servers responded to queries."
        : ProbeResults.Any(probe => probe.Attempted && !probe.HasResponse)
            ? "Some attempted authoritative queries did not return a response."
            : "Authoritative server responsiveness could not be confirmed because coverage is incomplete.";
}
