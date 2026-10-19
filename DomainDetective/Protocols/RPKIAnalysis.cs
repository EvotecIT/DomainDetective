using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Validates IP prefixes against RPKI data.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class RPKIAnalysis : IHasAssessments {
    /// <summary>DNS configuration for lookups.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Override DNS queries for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Override RPKI queries for testing.</summary>
    public Func<string, Task<(string Prefix, int Asn, bool Valid)>>? QueryRpkiOverride { private get; set; }

    /// <summary>HTTP client for RIPE requests. The caller retains ownership of supplied clients.</summary>
    public HttpClient HttpClient { get; set; } = SharedHttpClient.Instance;

    /// <summary>Results for each IP address.</summary>
    public List<RPKIResult> Results { get; private set; } = new();
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; set; }
    /// <summary>Structured assessments captured during RPKI analysis.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>True when all IPs are valid per RPKI.</summary>
    public bool AllValid => Results.Count > 0 && Results.All(r => r.Valid);

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken ct) {
        ct.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null) {
            return await QueryDnsOverride(name, type);
        }
        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: ct);
    }

    private async Task<(string Prefix, int Asn, RpkiValidationState State)> QueryRpki(string ip, InternalLogger? logger, CancellationToken ct) {
        string? prefix = null;
        if (QueryRpkiOverride != null) {
            try {
                var result = await QueryRpkiOverride(ip);
                ct.ThrowIfCancellationRequested();
                return (result.Prefix, result.Asn, result.Valid ? RpkiValidationState.Valid : RpkiValidationState.Unspecified);
            } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
                throw;
            } catch (Exception ex) {
                return Fail(prefix, logger, "RPKI query failed for {0}: {1}", ip, ex.Message);
            }
        }

        try {
            if (!IPAddress.TryParse(ip, out _)) {
                return Fail(prefix, logger, "Invalid IP address for RPKI lookup: {0}.", ip);
            }
            HttpClient client = HttpClient;
            var overview = await Helpers.IpNetworkMetadata.PrefixAsync(client, ip, ct).ConfigureAwait(false);
            prefix = overview.Prefix;
            int asn = overview.Asn;
            string? status = await Helpers.IpNetworkMetadata.RpkiStatusAsync(client, prefix, asn, ct).ConfigureAwait(false);
            RpkiValidationState state = status?.ToLowerInvariant() switch {
                "valid" => RpkiValidationState.Valid,
                "invalid_asn" => RpkiValidationState.InvalidOriginAsn,
                "invalid_length" => RpkiValidationState.InvalidPrefixLength,
                "invalid" => RpkiValidationState.Invalid,
                "unknown" => RpkiValidationState.NotFound,
                _ => RpkiValidationState.QueryFailed
            };
            if (state == RpkiValidationState.QueryFailed) {
                return Fail(prefix, logger, "Unsupported RPKI validation status for {0}: {1}.", ip, status ?? "<missing>");
            }
            return (prefix ?? string.Empty, asn, state);
        } catch (OperationCanceledException) when (ct.IsCancellationRequested) {
            throw;
        } catch (Exception ex) {
            return Fail(prefix, logger, "RPKI query failed for {0}: {1}", ip, ex.Message);
        }
    }

    private static (string Prefix, int Asn, RpkiValidationState State) Fail(string? prefix, InternalLogger? logger, string message, params object[] args) {
        // External dependency failures (HTTP 5xx/timeouts) should not surface as hard errors.
        // Downgrade to a warning so pipelines keep flowing without red error records.
        logger?.WriteWarningCode(RpkiCodes.QueryFailed, message, args);
        return (prefix ?? string.Empty, 0, RpkiValidationState.QueryFailed);
    }

    /// <summary>
    /// Validates IP addresses of <paramref name="domainName"/> against RPKI repositories.
    /// </summary>
    public async Task Analyze(string domainName, InternalLogger? logger = null, CancellationToken ct = default) {
        using var observations = Helpers.ScanObservations.Current == null ? new Helpers.ScanObservations() : null;
        Subject = domainName;
        Results = new List<RPKIResult>();
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "RPKI", target: domainName) : null;
        var a = await QueryDns(domainName, DnsRecordType.A, ct);
        var aaaa = await QueryDns(domainName, DnsRecordType.AAAA, ct);

        var addresses = a.Concat(aaaa)
            .Select(r => r.Data)
            .Distinct(StringComparer.Ordinal);

        var tasks = addresses.Select(async ip => {
            ct.ThrowIfCancellationRequested();
            var (prefix, asn, state) = await QueryRpki(ip, logger, ct);
            bool valid = state == RpkiValidationState.Valid;
            lock (Results) {
                Results.Add(new RPKIResult {
                    IpAddress = ip,
                    Prefix = prefix,
                    Asn = asn,
                    ValidationState = state,
                    Valid = valid
                });
            }

            if (!string.IsNullOrWhiteSpace(prefix)) {
                logger?.WriteInformationCode(RpkiCodes.PrefixCovered, $"IP {ip} covered by {prefix} (AS{asn}).");
                if (valid) {
                    logger?.WriteInformationCode(RpkiCodes.ValidRoa, $"ROA valid for {prefix} (AS{asn}).");
                }
            }
        });

        await Task.WhenAll(tasks);

        // Roll-up positive when every checked IP is covered by a valid ROA
        try {
            if (Results.Count > 0 && AllValid)
            {
                logger?.WriteInformationCode(RpkiCodes.AllValid, "All apex IPs covered by valid ROAs");
            }
        } catch { /* best effort */ }
    }
}

/// <summary>Represents RPKI validation for a single IP.</summary>
/// <para>Part of the DomainDetective project.</para>
public class RPKIResult {
    /// <summary>IP address being verified.</summary>
    public string IpAddress { get; init; } = string.Empty;
    /// <summary>Origin prefix as reported by RIPE.</summary>
    public string Prefix { get; init; } = string.Empty;
    /// <summary>Origin ASN.</summary>
    public int Asn { get; init; }
    /// <summary>Indicates whether the prefix is valid.</summary>
    public bool Valid { get; init; }
    /// <summary>ROA validation outcome, including missing ROAs and failed queries.</summary>
    public RpkiValidationState ValidationState { get; init; }
}
