using DnsClientX;
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
                result = await ProbeServerAsync(domainName, host, ip, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
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

    private async Task<DnsAmplificationServerResult> ProbeServerAsync(string domainName, string nsHost, IPAddress ip, CancellationToken ct)
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

#if NET6_0_OR_GREATER
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
        bool hasProbe = worst != null && worst.ResponseBytes > 0;
        bool largeUdp = hasProbe && worst!.ResponseBytes > LargeUdpResponseThreshold && !worst.Truncated;
        bool highAmp = hasProbe && worst!.AmplificationFactor >= HighAmplificationFactorThreshold && !worst.Truncated;
        bool ednsOversize = result.EdnsSupported && (result.EdnsUdpPayloadSize ?? 0) > LargeUdpResponseThreshold;

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

        if (largeUdp || highAmp)
        {
            var q = worst!;
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

    private static byte[] EncodeDomainName(string name)
    {
        var parts = name.TrimEnd('.').Split('.');
        using var ms = new System.IO.MemoryStream();
        foreach (var part in parts)
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(part);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] BuildQuery(string domain, DnsRecordType qtype, bool recursionDesired, bool includeEdns, int clientUdpPayloadSize, bool dnsSecOk)
    {
        var header = new byte[12];
        var id = Helpers.DnsQueryIdGenerator.NextUShort();
        header[0] = (byte)(id >> 8);
        header[1] = (byte)id;
        header[2] = recursionDesired ? (byte)0x01 : (byte)0x00; // RD in low byte of flags
        header[5] = 0x01; // QDCOUNT
        if (includeEdns)
        {
            header[11] = 0x01; // ARCOUNT (OPT)
        }

        var qname = EncodeDomainName(domain);
        int additional = includeEdns ? 11 : 0;
        var query = new byte[header.Length + qname.Length + 4 + additional];
        Buffer.BlockCopy(header, 0, query, 0, header.Length);
        Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
        var offset = header.Length + qname.Length;
        query[offset] = (byte)(((ushort)qtype) >> 8);
        query[offset + 1] = (byte)((ushort)qtype);
        query[offset + 2] = 0x00;
        query[offset + 3] = 0x01; // IN
        offset += 4;

        if (!includeEdns)
        {
            return query;
        }

        // OPT RR
        query[offset] = 0x00;
        query[offset + 1] = 0x00;
        query[offset + 2] = 0x29;
        query[offset + 3] = (byte)(clientUdpPayloadSize >> 8);
        query[offset + 4] = (byte)(clientUdpPayloadSize & 0xFF);
        query[offset + 5] = 0x00; // ext rcode
        query[offset + 6] = 0x00; // version
        query[offset + 7] = dnsSecOk ? (byte)0x80 : (byte)0x00; // flags high byte (DO=1)
        query[offset + 8] = 0x00; // flags low byte
        query[offset + 9] = 0x00;
        query[offset + 10] = 0x00; // RDLEN = 0
        return query;
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
        if (data == null || data.Length < 12)
        {
            return false;
        }

        ushort flags = (ushort)((data[2] << 8) | data[3]);
        header = new DnsHeaderInfo
        {
            Truncated = (flags & 0x0200) != 0,
            RecursionAvailable = (flags & 0x0080) != 0,
            Rcode = flags & 0x000F
        };
        return true;
    }

    private static void SkipName(byte[] buffer, ref int offset)
    {
        int jumps = 0;
        while (true)
        {
            if (offset >= buffer.Length)
            {
                offset = buffer.Length;
                return;
            }

            var len = buffer[offset++];
            if (len == 0)
            {
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                if (offset < buffer.Length)
                {
                    offset++;
                }
                break;
            }

            offset += len;
            if (++jumps > 50)
            {
                break;
            }
        }
    }

    private static ushort ReadUInt16(byte[] buffer, ref int offset)
    {
        if (offset + 2 > buffer.Length)
        {
            offset = buffer.Length;
            return 0;
        }
        var v = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        offset += 2;
        return v;
    }

    private static uint ReadUInt32(byte[] buffer, ref int offset)
    {
        if (offset + 4 > buffer.Length)
        {
            offset = buffer.Length;
            return 0;
        }
        uint v = (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
        offset += 4;
        return v;
    }

    private static bool TryParseEdns(byte[] data, out (bool supported, int udpPayloadSize) edns)
    {
        edns = default;
        if (data == null || data.Length < 12)
        {
            return false;
        }

        int offset = 4;
        var qd = ReadUInt16(data, ref offset);
        var an = ReadUInt16(data, ref offset);
        var ns = ReadUInt16(data, ref offset);
        var ar = ReadUInt16(data, ref offset);

        offset = 12;
        for (int i = 0; i < qd; i++)
        {
            SkipName(data, ref offset);
            offset += 4;
            if (offset >= data.Length)
            {
                return false;
            }
        }

        int rrCount = an + ns + ar;
        for (int i = 0; i < rrCount; i++)
        {
            SkipName(data, ref offset);
            var type = ReadUInt16(data, ref offset);
            var rrClass = ReadUInt16(data, ref offset);
            _ = ReadUInt32(data, ref offset);
            var rdlen = ReadUInt16(data, ref offset);
            if (offset + rdlen > data.Length)
            {
                return false;
            }
            if (type == 41)
            {
                edns = (supported: true, udpPayloadSize: rrClass);
                return true;
            }
            offset += rdlen;
        }

        edns = (supported: false, udpPayloadSize: 0);
        return true;
    }
}
