using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Determines whether name servers respond to EDNS queries.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public record EdnsSupportInfo
{
    /// <summary>Whether the capability query completed. Failed queries do not establish EDNS support.</summary>
    public bool QuerySucceeded { get; init; } = true;

    /// <summary>Failure details when the capability query could not complete.</summary>
    public string? Error { get; init; }

    /// <summary>Whether EDNS is supported.</summary>
    public bool Supported { get; init; }

    /// <summary>The UDP payload size advertised by the server.</summary>
    public int UdpPayloadSize { get; init; }

    /// <summary>Indicates if the DO bit was set in the response.</summary>
    public bool DoBit { get; init; }

    /// <summary>Indicates the UDP response was truncated and TCP fallback was necessary.</summary>
    public bool TruncatedUdp { get; init; }

    /// <summary>EDNS version reported by the server.</summary>
    public int Version { get; init; }

    /// <summary>True when the server returned a DNS COOKIE option (RFC 7873).</summary>
    public bool CookieSupported { get; init; }

    /// <summary>Length (bytes) of the COOKIE option data when present.</summary>
    public int CookieLength { get; init; }
}

/// <summary>
/// Performs EDNS capability checks against authoritative servers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class EdnsSupportAnalysis : IHasAssessments
{
    /// <summary>Domain under analysis.</summary>
    public string? Subject { get; set; }
    /// <summary>EDNS support results keyed by server.</summary>
    public Dictionary<string, EdnsSupportInfo> ServerSupport { get; private set; } = new();

    /// <summary>Configuration for DNS queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Budget for one name-server or address discovery query. Increase it when the configured resolver fallback needs more time.</summary>
    public TimeSpan DiscoveryTimeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Allows overriding DNS queries for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Allows overriding server queries for testing.</summary>
    public Func<string, Task<EdnsSupportInfo>>? QueryServerOverride { private get; set; }

    /// <summary>Relevant standards for EDNS analysis.</summary>
    public IReadOnlyList<StandardReference> RfcReferences => new[] {
        new StandardReference { Title = "Extension Mechanisms for DNS (EDNS(0))", Reference = "RFC 6891", Url = "https://datatracker.ietf.org/doc/html/rfc6891" }
    };

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(DiscoveryTimeout);
        var answers = QueryDnsOverride != null
            ? await QueryDnsOverride(name, type).WaitWithCancellation(deadline.Token).ConfigureAwait(false)
            : await DnsConfiguration.QueryDNS(name, type, cancellationToken: deadline.Token).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return answers;
    }

    private static (string Host, int Port) ParseServerEndpoint(string server)
    {
        if (string.IsNullOrWhiteSpace(server))
        {
            return (string.Empty, 53);
        }

        var trimmed = server.Trim();
        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var closingBracket = trimmed.IndexOf(']');
            if (closingBracket > 0)
            {
                var host = trimmed.Substring(1, closingBracket - 1);
                if (closingBracket + 1 < trimmed.Length &&
                    trimmed[closingBracket + 1] == ':' &&
                    int.TryParse(trimmed.Substring(closingBracket + 2), out var bracketedPort))
                {
                    return (host, bracketedPort);
                }

                return (host, 53);
            }
        }

        if (trimmed.Count(c => c == ':') == 1)
        {
            var separatorIndex = trimmed.LastIndexOf(':');
            if (separatorIndex > 0 &&
                separatorIndex < trimmed.Length - 1 &&
                int.TryParse(trimmed.Substring(separatorIndex + 1), out var parsedPort))
            {
                return (trimmed.Substring(0, separatorIndex), parsedPort);
            }
        }

        return (trimmed, 53);
    }

    private static async Task<EdnsSupportInfo> QueryServerAsync(string ip, string queryDomain, CancellationToken cancellationToken)
    {
        var (host, port) = ParseServerEndpoint(ip);
        byte[] cookie = new byte[8];
        try {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(cookie);
        } catch { /* best-effort */ }
        var query = new DnsMessage(queryDomain, DnsRecordType.A, new DnsMessageOptions(
            EnableEdns: true,
            UdpBufferSize: 4096,
            Options: new[] { new CookieOption(cookie) },
            RecursionDesired: false));
        DnsWireQueryResult result = await DnsWireQueryClient.QueryUdpAsync(
            host, port, query, 3000, useTcpFallback: true, cancellationToken: cancellationToken).ConfigureAwait(false);
        DnsResponse response = result.Response;
        return new EdnsSupportInfo {
            Supported = response.EdnsUdpPayloadSize.HasValue,
            UdpPayloadSize = response.EdnsUdpPayloadSize ?? 0,
            DoBit = response.EdnsDnsSecOk,
            TruncatedUdp = response.UsedTransport == Transport.Tcp,
            Version = response.EdnsVersion ?? 0,
            CookieSupported = response.EdnsCookie.Length > 0,
            CookieLength = response.EdnsCookie.Length
        };
    }

    /// <summary>
    /// Queries authoritative servers to determine EDNS support.
    /// </summary>
    /// <param name="domainName">Domain name.</param>
    /// <param name="logger">Optional logger.</param>
    public Task Analyze(string domainName, InternalLogger? logger) => Analyze(domainName, logger, CancellationToken.None);

    /// <summary>Queries authoritative servers, retaining failures per server and honoring caller cancellation.</summary>
    /// <param name="domainName">Domain name.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="cancellationToken">Token to cancel discovery and capability queries.</param>
    public async Task Analyze(string domainName, InternalLogger? logger, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Subject = domainName;
        Assessments.Clear();
        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "EDNS", target: domainName) : null;
        ServerSupport.Clear();
        var ns = await QueryDns(domainName, DnsRecordType.NS, cancellationToken);
        using var discoveryGate = new SemaphoreSlim(4);
        var discoveries = await Task.WhenAll(ns.Select(record => record.Data.Trim('.')).Distinct(StringComparer.OrdinalIgnoreCase).Select(async host => {
            await discoveryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try {
                var aTask = QueryDns(host, DnsRecordType.A, cancellationToken);
                var aaaaTask = QueryDns(host, DnsRecordType.AAAA, cancellationToken);
                try { await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OutOfMemoryException) { cancellationToken.ThrowIfCancellationRequested(); }
                var a = aTask.Status == TaskStatus.RanToCompletion ? aTask.Result : Array.Empty<DnsAnswer>();
                var aaaa = aaaaTask.Status == TaskStatus.RanToCompletion ? aaaaTask.Result : Array.Empty<DnsAnswer>();
                return (Host: host, Addresses: a.Concat(aaaa).Select(answer => answer.Data ?? answer.DataRaw)
                    .Where(address => !string.IsNullOrWhiteSpace(address)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                    Failed: aTask.Status != TaskStatus.RanToCompletion || aaaaTask.Status != TaskStatus.RanToCompletion);
            } finally { discoveryGate.Release(); }
        })).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var targets = discoveries.SelectMany(item => item.Addresses.Select(address => (item.Host, Address: address))).ToArray();
        using var gate = new SemaphoreSlim(8);
        var results = await Task.WhenAll(targets.Select(async target => {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try {
                var support = QueryServerOverride != null
                    ? await QueryServerOverride(target.Address).WaitWithCancellation(cancellationToken).ConfigureAwait(false)
                    : await QueryServerAsync(target.Address, domainName, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return (target.Host, target.Address, Support: support);
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is not OutOfMemoryException) {
                cancellationToken.ThrowIfCancellationRequested();
                return (target.Host, target.Address, Support: new EdnsSupportInfo { QuerySucceeded = false, Error = $"{ex.GetType().Name}: {ex.Message}" });
            } finally { gate.Release(); }
        })).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var discovery in discoveries.Where(item => item.Failed)) {
            ServerSupport[$"{discovery.Host} (address discovery)"] = new EdnsSupportInfo {
                QuerySucceeded = false, Error = "Name-server address discovery was incomplete."
            };
            logger?.WriteErrorCode(EdnsCodes.QueryFailed, "EDNS address discovery was incomplete for {0}.", discovery.Host);
        }
        foreach (var result in results) {
            var host = result.Host;
            var serverAddress = result.Address;
            var support = result.Support;
            ServerSupport[$"{host} ({serverAddress})"] = support;
            if (!support.QuerySucceeded)
            {
                logger?.WriteErrorCode(EdnsCodes.QueryFailed, "EDNS query failed on {0} ({1}): {2}", host, serverAddress, support.Error);
                continue;
            }
            logger?.WriteVerbose("EDNS support for {0} ({1}): {2}", host, serverAddress, support.Supported);
            if (!support.Supported)
            {
                logger?.WriteWarningCode(EdnsCodes.NotSupported, "EDNS not supported on {0} ({1})", host, serverAddress);
            }
            else
            {
                logger?.WriteInformationCode(EdnsCodes.Supported, "EDNS supported on {0} ({1})", host, serverAddress);
                if (support.CookieSupported)
                {
                    logger?.WriteInformationCode(EdnsCodes.CookiesSupported, "DNS Cookies supported on {0} ({1})", host, serverAddress);
                }
                else
                {
                    logger?.WriteWarningCode(EdnsCodes.CookiesNotSupported, "DNS Cookies not supported on {0} ({1})", host, serverAddress);
                }
                if (support.UdpPayloadSize > 1232)
                {
                    logger?.WriteWarningCode(EdnsCodes.BufferTooLarge, "EDNS UDP payload {0} on {1} ({2}) > 1232", support.UdpPayloadSize, host, serverAddress);
                }
                else
                {
                    logger?.WriteInformationCode(EdnsCodes.UdpSizeOk, "EDNS UDP payload {0} on {1} ({2})", support.UdpPayloadSize, host, serverAddress);
                }
                if (support.Version == 0)
                {
                    logger?.WriteInformationCode(EdnsCodes.VersionZero, "EDNS version 0 on {0} ({1})", host, serverAddress);
                }
                if (support.TruncatedUdp)
                {
                    logger?.WriteInformationCode(EdnsCodes.TruncatedFallback, "EDNS response truncated on {0} ({1}); TCP fallback used", host, serverAddress);
                }
            }
        }
    }

    /// <summary>Gets the assessments value.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
