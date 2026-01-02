using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed record DnsOverTlsEndpointResult
{
    public string NameServerHost { get; init; } = string.Empty;
    public string ServerIp { get; init; } = string.Empty;
    public int Port { get; init; }
    public bool Supported { get; init; }
    public string? Protocol { get; init; }
    public string? CipherSuite { get; init; }
    public bool? HostnameMatch { get; init; }
    public bool? CertificateValid { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Detects DNS over TLS (DoT, RFC 7858) support on a domain's authoritative name servers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsOverTlsAnalysis : IHasAssessments
{
    public string? Subject { get; set; }

    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Maximum time allowed per TLS probe.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(6);

    /// <summary>Port used for DNS over TLS (DoT).</summary>
    public int Port { get; set; } = 853;

    /// <summary>Max servers (A/AAAA endpoints) to probe to avoid aggressive scanning.</summary>
    public int MaxServersToProbe { get; set; } = 12;

    public Dictionary<string, DnsOverTlsEndpointResult> ServerResults { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Optional override for DNS queries (NS/A/AAAA discovery) used in tests.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Optional override for DoT probes used in tests.</summary>
    public Func<string, IPAddress, int, TimeSpan, CancellationToken, Task<DnsOverTlsEndpointResult>>? ProbeOverride { get; set; }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSOVERTLS", target: domainName);
        Subject = domainName;
        Assessments.Clear();
        ServerResults.Clear();

        var nsAnswers = await QueryDns(domainName, DnsRecordType.NS, cancellationToken).ConfigureAwait(false);
        var nsHosts = nsAnswers
            .Select(a => (a.Data ?? a.DataRaw ?? string.Empty).Trim('.'))
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (nsHosts.Length == 0)
        {
            logger.WriteInformationCode(DnsOverTlsCodes.NameServersMissing, "No authoritative name servers found for {0}", domainName);
            return;
        }

        var endpoints = new List<(string host, IPAddress ip)>();
        foreach (var host in nsHosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var ans in await QueryDns(host, DnsRecordType.A, cancellationToken).ConfigureAwait(false))
            {
                if (IPAddress.TryParse(ans.Data ?? ans.DataRaw, out var ip))
                {
                    endpoints.Add((host, ip));
                }
            }
            foreach (var ans in await QueryDns(host, DnsRecordType.AAAA, cancellationToken).ConfigureAwait(false))
            {
                if (IPAddress.TryParse(ans.Data ?? ans.DataRaw, out var ip))
                {
                    endpoints.Add((host, ip));
                }
            }
        }

        endpoints = endpoints
            .GroupBy(e => $"{e.host}|{e.ip}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(MaxServersToProbe)
            .ToList();

        if (endpoints.Count == 0)
        {
            logger.WriteWarningCode(DnsOverTlsCodes.NameServerAddressesMissing, "Name servers discovered for {0}, but none resolved to A/AAAA addresses", domainName);
            return;
        }

        int supported = 0;
        foreach (var (host, ip) in endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = $"{host} ({ip})";
            using var _scope = collector.PushTarget(key);
            DnsOverTlsEndpointResult result;
            try
            {
                result = await ProbeDotAsync(host, ip, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
            {
                logger.WriteWarningCode(DnsOverTlsCodes.ProbeFailed, "DNS over TLS probe failed: {0}", ex.Message);
                result = new DnsOverTlsEndpointResult
                {
                    NameServerHost = host,
                    ServerIp = ip.ToString(),
                    Port = Port,
                    Supported = false,
                    Error = ex.Message
                };
            }

            ServerResults[key] = result;
            if (result.Supported)
            {
                supported++;
                logger.WriteInformationCode(DnsOverTlsCodes.Supported, "DNS over TLS supported on {0} ({1}:{2})", host, ip, Port);

                if (result.HostnameMatch == false)
                {
                    logger.WriteWarningCode(DnsOverTlsCodes.CertificateMismatch, "DNS over TLS certificate hostname mismatch on {0} ({1}:{2})", host, ip, Port);
                }
                if (result.CertificateValid == false)
                {
                    logger.WriteWarningCode(DnsOverTlsCodes.CertificateInvalid, "DNS over TLS certificate validation failed on {0} ({1}:{2})", host, ip, Port);
                }
            }
        }

        if (supported == 0)
        {
            logger.WriteWarningCode(DnsOverTlsCodes.NotSupported, "DNS over TLS is not supported on authoritative name servers for {0}", domainName);
        }
    }

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type).ConfigureAwait(false);
        }
        return await DnsConfiguration.QueryDNS(name, type, cancellationToken: ct).ConfigureAwait(false);
    }

    private async Task<DnsOverTlsEndpointResult> ProbeDotAsync(string nsHost, IPAddress ip, CancellationToken ct)
    {
        if (ProbeOverride != null)
        {
            return await ProbeOverride(nsHost, ip, Port, Timeout, ct).ConfigureAwait(false);
        }

        try
        {
            using var tls = await TlsProbe.ProbeAsync(ip, nsHost, Port, Timeout, ct).ConfigureAwait(false);
            return new DnsOverTlsEndpointResult
            {
                NameServerHost = nsHost,
                ServerIp = ip.ToString(),
                Port = Port,
                Supported = true,
                Protocol = tls.Protocol.ToString(),
                CipherSuite = tls.CipherSuite,
                HostnameMatch = tls.HostnameMatch,
                CertificateValid = tls.CertificateValid,
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            return new DnsOverTlsEndpointResult
            {
                NameServerHost = nsHost,
                ServerIp = ip.ToString(),
                Port = Port,
                Supported = false,
                Error = ex.Message
            };
        }
    }
}
