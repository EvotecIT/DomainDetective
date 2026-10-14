using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Detects DNS over TLS (DoT, RFC 7858) support on a domain's authoritative name servers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed partial class DnsOverTlsAnalysis : IHasAssessments
{
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }

    /// <summary>Gets or sets the dns configuration value.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Maximum time allowed per TLS probe.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(6);

    /// <summary>Port used for DNS over TLS (DoT).</summary>
    public int Port { get; set; } = 853;

    /// <summary>Max servers (A/AAAA endpoints) to probe to avoid aggressive scanning.</summary>
    public int MaxServersToProbe { get; set; } = 12;

    /// <summary>Gets or sets the server results value.</summary>
    public Dictionary<string, DnsOverTlsEndpointResult> ServerResults { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Optional override for DNS queries (NS/A/AAAA discovery) used in tests.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Optional override for DoT probes used in tests.</summary>
    public Func<string, IPAddress, int, TimeSpan, CancellationToken, Task<DnsOverTlsEndpointResult>>? ProbeOverride { get; set; }

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Maximum concurrent discovery or endpoint probes.</summary>
    public int QueryConcurrency { get; set; } = 6;
    /// <summary>Total discovery and probing deadline; unfinished endpoints retain budget evidence.</summary>
    public TimeSpan AnalysisTimeout { get; set; } = TimeSpan.FromSeconds(10);
    /// <summary>Gets address-discovery failures, keyed by nameserver and record type.</summary>
    public Dictionary<string, string> DiscoveryErrors { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets whether discovery and all planned probes completed without a scan-cap omission.</summary>
    public bool CoverageComplete { get; private set; }
    /// <summary>Gets the number of endpoints discovered before the scan cap.</summary>
    public int DiscoveredEndpointCount { get; private set; }

    /// <summary>Runs bounded DoT probes without treating timeout or optional service absence as a domain defect.</summary>
    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
        if (Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(Timeout));
        if (AnalysisTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(AnalysisTimeout));
        if (MaxServersToProbe <= 0) throw new ArgumentOutOfRangeException(nameof(MaxServersToProbe));
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSOVERTLS", target: domainName);
        Subject = domainName;
        Assessments.Clear(); ServerResults.Clear(); DiscoveryErrors.Clear();
        CoverageComplete = false; DiscoveredEndpointCount = 0;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(AnalysisTimeout);
        var nsResult = await DiscoverAsync(domainName, DnsRecordType.NS, budget.Token, cancellationToken).ConfigureAwait(false);
        if (nsResult.Error != null) DiscoveryErrors[domainName + " NS"] = nsResult.Error;
        string[] hosts = nsResult.Answers.Select(answer => answer.Data.TrimEnd('.'))
            .Where(host => !string.IsNullOrWhiteSpace(host)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (hosts.Length == 0) {
            if (DiscoveryErrors.Count > 0) logger.WriteWarningCode(DnsOverTlsCodes.CoverageIncomplete, "DoT nameserver discovery did not complete.");
            else logger.WriteInformationCode(DnsOverTlsCodes.NameServersMissing, "No authoritative name servers found for {0}", domainName);
            return;
        }
        var queries = hosts.SelectMany(host => new[] { (host, DnsRecordType.A), (host, DnsRecordType.AAAA) }).ToArray();
        var addresses = await BoundedAsyncWork.MapAsync(queries.Length, QueryConcurrency, index =>
            DiscoverAsync(queries[index].host, queries[index].Item2, budget.Token, cancellationToken)).ConfigureAwait(false);
        for (int i = 0; i < queries.Length; i++) {
            if (addresses[i].Error != null) DiscoveryErrors[$"{queries[i].host} {queries[i].Item2}"] = addresses[i].Error!;
        }
        var endpoints = new List<(string host, IPAddress ip)>();
        for (int i = 0; i < hosts.Length; i++) {
            var found = addresses[i * 2].Answers.Concat(addresses[i * 2 + 1].Answers)
                .Select(answer => IPAddress.TryParse(answer.Data, out var ip) ? ip : null)
                .Where(ip => ip != null).Select(ip => ip!).Distinct().ToArray();
            if (found.Length == 0) DiscoveryErrors[hosts[i]] = "No nameserver address was established.";
            endpoints.AddRange(found.Select(ip => (hosts[i], ip)));
        }
        DiscoveredEndpointCount = endpoints.Count;
        var planned = endpoints.Take(MaxServersToProbe).ToArray();
        if (planned.Length == 0) {
            logger.WriteWarningCode(DnsOverTlsCodes.CoverageIncomplete, "No authoritative endpoint was available for DoT probing.");
            return;
        }
        var results = await BoundedAsyncWork.MapAsync(planned.Length, QueryConcurrency, index =>
            RunProbeAsync(planned[index].host, planned[index].ip, domainName, budget.Token, cancellationToken)).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var result in results) {
            string key = $"{result.NameServerHost} ({result.ServerIp})";
            ServerResults[key] = result;
            using var scope = collector.PushTarget(key);
            if (result.Supported) {
                logger.WriteInformationCode(DnsOverTlsCodes.Supported, "DNS over TLS supported on {0}", key);
            } else if (result.Outcome == DnsOverTlsProbeOutcome.ConnectionRefused) {
                logger.WriteInformationCode(DnsOverTlsCodes.NotSupported, "TCP/{0} connection was refused from this observation point", Port);
            } else {
                logger.WriteWarningCode(DnsOverTlsCodes.ProbeFailed, "DoT evidence is incomplete ({0}): {1}", result.FailureStage ?? "probe", result.Error ?? "Unknown result");
            }
            if (result.TlsHandshakeSucceeded || result.Supported) {
                if (result.HostnameMatch == false) logger.WriteWarningCode(DnsOverTlsCodes.CertificateMismatch, "DNS over TLS certificate hostname mismatch on {0}", key);
                if (result.CertificateValid == false) logger.WriteWarningCode(DnsOverTlsCodes.CertificateInvalid, "DNS over TLS certificate validation failed on {0}", key);
            }
        }
        CoverageComplete = DiscoveryErrors.Count == 0 && planned.Length == DiscoveredEndpointCount
            && results.All(result => result.Outcome == DnsOverTlsProbeOutcome.Supported || result.Outcome == DnsOverTlsProbeOutcome.ConnectionRefused);
        if (!CoverageComplete) logger.WriteWarningCode(DnsOverTlsCodes.CoverageIncomplete, "DoT coverage is incomplete; support cannot be confirmed for every authoritative endpoint.");
    }
}
