using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed record DnsAmplificationProbeResult
{
    public string QueryName { get; init; } = string.Empty;
    public DnsRecordType QueryType { get; init; }
    public int ClientUdpPayloadSize { get; init; }
    public bool DnsSecOk { get; init; }
    public int QueryBytes { get; init; }
    public int ResponseBytes { get; init; }
    public bool Truncated { get; init; }
    public int Rcode { get; init; }
    public double AmplificationFactor { get; init; }
}

public sealed record DnsAmplificationServerResult
{
    public string NameServerHost { get; init; } = string.Empty;
    public string ServerIp { get; init; } = string.Empty;

    public bool OpenRecursion { get; init; }
    public int? RecursionRcode { get; init; }

    public bool EdnsSupported { get; init; }
    public int? EdnsUdpPayloadSize { get; init; }
    public bool EdnsTruncatedUdp { get; init; }

    public IReadOnlyList<DnsAmplificationProbeResult> Probes { get; init; } = Array.Empty<DnsAmplificationProbeResult>();
}

/// <summary>
/// Evaluates DNS amplification posture for a domain's authoritative name servers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsAmplificationAnalysis : IHasAssessments
{
    private const int MaxServersToProbeUpperBound = 50;
    private static readonly TimeSpan MaxTimeoutUpperBound = TimeSpan.FromSeconds(15);

    public string? Subject { get; set; }

    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Maximum time allowed per UDP probe.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(4);

    /// <summary>Max servers (A/AAAA endpoints) to probe to avoid aggressive scanning.</summary>
    public int MaxServersToProbe { get; set; } = 12;

    /// <summary>UDP response size considered "large" for amplification posture.</summary>
    public int LargeUdpResponseThreshold { get; set; } = 1232;

    /// <summary>Amplification factor considered high (response/query).</summary>
    public double HighAmplificationFactorThreshold { get; set; } = 20.0;

    public Dictionary<string, DnsAmplificationServerResult> ServerResults { get; private set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Optional override for DNS queries (NS/A/AAAA discovery) used in tests.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Optional override for raw UDP queries used in tests.</summary>
    public Func<IPAddress, byte[], CancellationToken, Task<byte[]?>>? QueryUdpOverride { get; set; }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSAMPLIFICATION", target: domainName);
        Subject = domainName;
        Assessments.Clear();
        ServerResults.Clear();
        NormalizeLimits(logger);

        var nsAnswers = await QueryDns(domainName, DnsRecordType.NS, cancellationToken).ConfigureAwait(false);
        var nsHosts = nsAnswers
            .Select(a => (a.Data ?? a.DataRaw ?? string.Empty).Trim('.'))
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (nsHosts.Length == 0)
        {
            logger.WriteInformationCode(DnsAmplificationCodes.NameServersMissing, "No authoritative name servers found for {0}", domainName);
            return;
        }

        var endpoints = new List<(string host, IPAddress ip)>();
        foreach (var host in nsHosts)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var aTask = QueryDns(host, DnsRecordType.A, cancellationToken);
            var aaaaTask = QueryDns(host, DnsRecordType.AAAA, cancellationToken);
            await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);

            foreach (var ans in aTask.Result)
            {
                if (IPAddress.TryParse(ans.Data ?? ans.DataRaw, out var ip))
                {
                    endpoints.Add((host, ip));
                }
            }
            foreach (var ans in aaaaTask.Result)
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
            logger.WriteWarningCode(DnsAmplificationCodes.NameServerAddressesMissing, "Name servers discovered for {0}, but none resolved to A/AAAA addresses", domainName);
            return;
        }

        foreach (var (host, ip) in endpoints)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var key = $"{host} ({ip})";
            using var _scope = collector.PushTarget(key);
            DnsAmplificationServerResult result;
            try
            {
                result = await ProbeServerAsync(domainName, host, ip, logger, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
            {
                logger.WriteWarningCode(DnsAmplificationCodes.CheckFailed, "DNS amplification probe failed: {0}", ex.Message);
                continue;
            }

            ServerResults[key] = result;
            EmitAssessmentsForServer(result, logger);
        }

        if (Assessments.Count == 0)
        {
            logger.WriteInformationCode(DnsAmplificationCodes.NoIndicators, "No amplification indicators were detected");
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

    private async Task<DnsAmplificationServerResult> ProbeServerAsync(string domainName, string nsHost, IPAddress ip, InternalLogger logger, CancellationToken ct)
    {
        // 1) Open recursion probe (RD=1) against an unrelated name.
        var recursionQuery = BuildQuery("example.com", DnsRecordType.A, recursionDesired: true, includeEdns: false, clientUdpPayloadSize: 0, dnsSecOk: false);
        var recursionResp = await QueryUdp(ip, recursionQuery, ct).ConfigureAwait(false);
        bool openRecursion = false;
        int? recursionRcode = null;
        if (recursionResp != null && TryParseHeader(recursionResp, out var recursionHeader))
        {
            openRecursion = recursionHeader.RecursionAvailable && recursionHeader.Rcode == 0;
            recursionRcode = recursionHeader.Rcode;
        }

        // 2) EDNS baseline (detect server payload size + truncation).
        const int baselinePayload = 4096;
        var ednsQuery = BuildQuery(domainName, DnsRecordType.NS, recursionDesired: false, includeEdns: true, clientUdpPayloadSize: baselinePayload, dnsSecOk: false);
        var ednsResp = await QueryUdp(ip, ednsQuery, ct).ConfigureAwait(false);

        bool ednsSupported = false;
        int? ednsUdpPayload = null;
        bool ednsTruncated = false;
        if (ednsResp != null && TryParseHeader(ednsResp, out var ednsHeader))
        {
            ednsTruncated = ednsHeader.Truncated;
            if (TryParseEdns(ednsResp, out var parsedEdns))
            {
                ednsSupported = parsedEdns.supported;
                ednsUdpPayload = parsedEdns.udpPayloadSize;
            }
            else
            {
                logger.WriteDebug("Failed to parse EDNS data from response for {0} ({1})", nsHost, ip);
            }
        }

        // 3) Bounded large-answer probes (domain-local).
        var probes = new List<DnsAmplificationProbeResult>();

        probes.Add(await ProbeAsync(domainName, DnsRecordType.DNSKEY, baselinePayload, dnsSecOk: true, ip, ct).ConfigureAwait(false));
        probes.Add(await ProbeAsync(domainName, DnsRecordType.TXT, baselinePayload, dnsSecOk: false, ip, ct).ConfigureAwait(false));

        return new DnsAmplificationServerResult
        {
            NameServerHost = nsHost,
            ServerIp = ip.ToString(),
            OpenRecursion = openRecursion,
            RecursionRcode = recursionRcode,
            EdnsSupported = ednsSupported,
            EdnsUdpPayloadSize = ednsUdpPayload,
            EdnsTruncatedUdp = ednsTruncated,
            Probes = probes
        };
    }

    private async Task<DnsAmplificationProbeResult> ProbeAsync(string qname, DnsRecordType qtype, int clientUdpPayloadSize, bool dnsSecOk, IPAddress server, CancellationToken ct)
    {
        var query = BuildQuery(qname, qtype, recursionDesired: false, includeEdns: true, clientUdpPayloadSize: clientUdpPayloadSize, dnsSecOk: dnsSecOk);
        var response = await QueryUdp(server, query, ct).ConfigureAwait(false);
        int respBytes = response?.Length ?? 0;
        bool truncated = false;
        int rcode = -1;
        if (response != null && TryParseHeader(response, out var h))
        {
            truncated = h.Truncated;
            rcode = h.Rcode;
        }

        double factor = 0;
        if (query.Length > 0 && respBytes > 0)
        {
            factor = (double)respBytes / query.Length;
        }

        return new DnsAmplificationProbeResult
        {
            QueryName = qname,
            QueryType = qtype,
            ClientUdpPayloadSize = clientUdpPayloadSize,
            DnsSecOk = dnsSecOk,
            QueryBytes = query.Length,
            ResponseBytes = respBytes,
            Truncated = truncated,
            Rcode = rcode,
            AmplificationFactor = factor
        };
    }

    private async Task<byte[]?> QueryUdp(IPAddress server, byte[] query, CancellationToken token)
    {
        if (QueryUdpOverride != null)
        {
            return await QueryUdpOverride(server, query, token).ConfigureAwait(false);
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
        cts.CancelAfter(Timeout);

        using var udp = new UdpClient(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
        udp.Client.ReceiveTimeout = (int)Math.Max(1000, Timeout.TotalMilliseconds);

        await udp.SendAsync(query, query.Length, new IPEndPoint(server, 53)).WaitWithCancellation(cts.Token).ConfigureAwait(false);

#if NET8_0_OR_GREATER
        var res = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
        return res.Buffer;
#else
        var res = await udp.ReceiveAsync().WaitWithCancellation(cts.Token).ConfigureAwait(false);
        return res.Buffer;
#endif
    }

    private void EmitAssessmentsForServer(DnsAmplificationServerResult result, InternalLogger logger)
    {
        var worst = result.Probes?.OrderByDescending(p => p.ResponseBytes).FirstOrDefault();
        bool ednsOversize = result.EdnsSupported && (result.EdnsUdpPayloadSize ?? 0) > LargeUdpResponseThreshold;

        bool largeUdp = false;
        bool highAmp = false;
        if (worst != null && worst.ResponseBytes > 0)
        {
            largeUdp = worst.ResponseBytes > LargeUdpResponseThreshold && !worst.Truncated;
            highAmp = worst.AmplificationFactor >= HighAmplificationFactorThreshold && !worst.Truncated;
        }

        if (result.OpenRecursion && (largeUdp || highAmp))
        {
            logger.WriteErrorCode(DnsAmplificationCodes.HighRisk, "Open recursion detected and large UDP responses observed; this server may be abused for reflection/amplification.");
            return;
        }

        if (result.OpenRecursion)
        {
            logger.WriteWarningCode(DnsAmplificationCodes.OpenRecursion, "Open recursion detected; the server may be abused for DNS amplification attacks.");
        }

        if (ednsOversize)
        {
            var udpSize = result.EdnsUdpPayloadSize ?? 0;
            logger.WriteWarningCode(DnsAmplificationCodes.EdnsUdpPayloadTooLarge, "Server advertises EDNS UDP payload size {0} (> {1})", udpSize, LargeUdpResponseThreshold);
        }

        if (worst != null && worst.ResponseBytes > 0 && (largeUdp || highAmp))
        {
            var q = worst;
            var msg = string.Format(
                CultureInfo.InvariantCulture,
                "Large UDP DNS response observed ({0} bytes, {1:F1}x) for {2} {3}.",
                q.ResponseBytes,
                q.AmplificationFactor,
                q.QueryType,
                q.QueryName);
            logger.WriteWarningCode(DnsAmplificationCodes.LargeUdpResponse, msg);
        }

        if (!result.OpenRecursion && !ednsOversize && !largeUdp && !highAmp)
        {
            logger.WriteInformationCode(DnsAmplificationCodes.NoIndicators, "No amplification indicators detected for this name server.");
        }
    }

    private void NormalizeLimits(InternalLogger logger)
    {
        if (Timeout <= TimeSpan.Zero)
        {
            logger.WriteVerbose("DNS amplification timeout was invalid ({0}); defaulting to 4 seconds", Timeout);
            Timeout = TimeSpan.FromSeconds(4);
        }
        else if (Timeout > MaxTimeoutUpperBound)
        {
            logger.WriteVerbose("DNS amplification timeout capped from {0} to {1}", Timeout, MaxTimeoutUpperBound);
            Timeout = MaxTimeoutUpperBound;
        }

        if (MaxServersToProbe <= 0)
        {
            logger.WriteVerbose("DNS amplification MaxServersToProbe was invalid ({0}); defaulting to 1", MaxServersToProbe);
            MaxServersToProbe = 1;
        }
        else if (MaxServersToProbe > MaxServersToProbeUpperBound)
        {
            logger.WriteVerbose("DNS amplification MaxServersToProbe capped from {0} to {1}", MaxServersToProbe, MaxServersToProbeUpperBound);
            MaxServersToProbe = MaxServersToProbeUpperBound;
        }
    }

    private static byte[] BuildQuery(string domain, DnsRecordType qtype, bool recursionDesired, bool includeEdns, int clientUdpPayloadSize, bool dnsSecOk)
    {
        var options = new DnsMessageOptions(
            RequestDnsSec: dnsSecOk,
            EnableEdns: includeEdns,
            UdpBufferSize: includeEdns ? clientUdpPayloadSize : 4096,
            RecursionDesired: recursionDesired);

        var message = new DnsMessage(domain, qtype, options);
        return message.SerializeDnsWireFormat();
    }

    private readonly struct DnsHeaderInfo
    {
        public bool Truncated { get; init; }
        public bool RecursionAvailable { get; init; }
        public int Rcode { get; init; }
    }

    private static bool TryParseHeader(byte[] data, out DnsHeaderInfo header)
    {
        header = default;
        if (!DnsWireMessageParser.TryParseHeader(data, out var parsed))
        {
            return false;
        }

        header = new DnsHeaderInfo
        {
            Truncated = parsed.IsTruncated,
            RecursionAvailable = parsed.IsRecursionAvailable,
            Rcode = (int)parsed.ResponseCode
        };
        return true;
    }

    private static bool TryParseEdns(byte[] data, out (bool supported, int udpPayloadSize) edns)
    {
        edns = default;
        if (!DnsWireMessageParser.TryParseEdns(data, out var parsed))
        {
            return false;
        }

        edns = (supported: parsed.Supported, udpPayloadSize: parsed.UdpPayloadSize);
        return true;
    }
}
