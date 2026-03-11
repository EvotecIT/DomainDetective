using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Determines whether name servers respond to EDNS queries.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public record EdnsSupportInfo
{
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

    /// <summary>Allows overriding DNS queries for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Allows overriding server queries for testing.</summary>
    public Func<string, Task<EdnsSupportInfo>>? QueryServerOverride { private get; set; }

    /// <summary>Relevant standards for EDNS analysis.</summary>
    public IReadOnlyList<StandardReference> RfcReferences => new[] {
        new StandardReference { Title = "Extension Mechanisms for DNS (EDNS(0))", Reference = "RFC 6891", Url = "https://datatracker.ietf.org/doc/html/rfc6891" }
    };

    private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type)
    {
        if (QueryDnsOverride != null)
        {
            return await QueryDnsOverride(name, type);
        }

        return await DnsConfiguration.QueryDNS(name, type);
    }

    private static byte[] EncodeDomainName(string domain)
    {
        var parts = domain.Split('.');
        using var ms = new System.IO.MemoryStream();
        foreach (var p in parts)
        {
            ms.WriteByte((byte)p.Length);
            var bytes = System.Text.Encoding.ASCII.GetBytes(p);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] BuildQuery(string domain, ushort id, byte[]? clientCookie)
    {
        var qname = EncodeDomainName(domain);

        bool includeCookie = clientCookie != null && clientCookie.Length == 8;
        int optLen = includeCookie ? 12 : 0; // option header (4) + client cookie (8)
        var query = new byte[12 + qname.Length + 4 + 11 + optLen];

        query[0] = (byte)(id >> 8);
        query[1] = (byte)id;
        query[2] = 0x01; // recursion desired
        query[5] = 0x01; // qdcount
        query[10] = 0x00;
        query[11] = 0x01; // arcount (OPT)

        Buffer.BlockCopy(qname, 0, query, 12, qname.Length);
        var offset = 12 + qname.Length;
        query[offset] = 0x00;
        query[offset + 1] = 0x01; // A
        query[offset + 2] = 0x00;
        query[offset + 3] = 0x01; // IN
        offset += 4;

        // OPT record
        query[offset] = 0x00; // root name
        query[offset + 1] = 0x00;
        query[offset + 2] = 0x29; // OPT
        query[offset + 3] = 0x10;
        query[offset + 4] = 0x00; // UDP payload size (4096)
        query[offset + 5] = 0x00;
        query[offset + 6] = 0x00;
        query[offset + 7] = 0x00;
        query[offset + 8] = 0x00; // TTL (ext rcode + version + flags)
        query[offset + 9] = 0x00;
        query[offset + 10] = (byte)(includeCookie ? 0x0C : 0x00); // RDLEN

        if (!includeCookie)
        {
            return query;
        }

        // COOKIE option (RFC 7873): code=10, len=8, client-cookie=8 bytes
        var optOffset = offset + 11;
        query[optOffset] = 0x00;
        query[optOffset + 1] = 0x0A;
        query[optOffset + 2] = 0x00;
        query[optOffset + 3] = 0x08;
        Buffer.BlockCopy(clientCookie!, 0, query, optOffset + 4, 8);
        return query;
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
                // compression pointer (2 bytes total)
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

    private static EdnsSupportInfo ParseEdns(byte[] data, byte[]? clientCookie)
    {
        if (data == null || data.Length < 12)
        {
            return new EdnsSupportInfo { Supported = false };
        }

        int offset = 0;
        offset += 4; // id+flags
        var qd = ReadUInt16(data, ref offset);
        var an = ReadUInt16(data, ref offset);
        var ns = ReadUInt16(data, ref offset);
        var ar = ReadUInt16(data, ref offset);

        // Skip questions
        offset = 12;
        for (int i = 0; i < qd; i++)
        {
            SkipName(data, ref offset);
            offset += 4; // type + class
            if (offset >= data.Length)
            {
                return new EdnsSupportInfo { Supported = false };
            }
        }

        int rrCount = an + ns + ar;
        for (int i = 0; i < rrCount; i++)
        {
            SkipName(data, ref offset);
            var type = ReadUInt16(data, ref offset);
            var rrClass = ReadUInt16(data, ref offset);
            var ttl = ReadUInt32(data, ref offset);
            var rdlen = ReadUInt16(data, ref offset);
            if (offset + rdlen > data.Length)
            {
                return new EdnsSupportInfo { Supported = false };
            }

            if (type == 41)
            {
                // OPT RR
                int udpPayload = rrClass;
                int version = (int)((ttl >> 16) & 0xFF);
                int flags = (int)(ttl & 0xFFFF);
                bool doBit = (flags & 0x8000) != 0;

                bool cookieSupported = false;
                int cookieLen = 0;
                int optOffset = offset;
                int optEnd = offset + rdlen;
                while (optOffset + 4 <= optEnd)
                {
                    var optCode = (ushort)((data[optOffset] << 8) | data[optOffset + 1]);
                    var optLen = (ushort)((data[optOffset + 2] << 8) | data[optOffset + 3]);
                    optOffset += 4;
                    if (optOffset + optLen > optEnd)
                    {
                        break;
                    }

                    if (optCode == 10)
                    {
                        cookieSupported = true;
                        cookieLen = optLen;
                        // Best-effort validation: server echoes client cookie in first 8 bytes.
                        if (clientCookie != null && clientCookie.Length == 8 && optLen >= 8)
                        {
                            // no-op: presence is enough; avoid strict matching to reduce false negatives
                        }
                    }

                    optOffset += optLen;
                }

                return new EdnsSupportInfo
                {
                    Supported = true,
                    UdpPayloadSize = udpPayload,
                    DoBit = doBit,
                    Version = version,
                    CookieSupported = cookieSupported,
                    CookieLength = cookieLen
                };
            }

            offset += rdlen;
        }

        return new EdnsSupportInfo { Supported = false };
    }

    private static async Task<int> ReadExactAsync(System.IO.Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer, offset + total, count - total, ct);
            if (read == 0) break;
            total += read;
        }
        return total;
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

    private static async Task<EdnsSupportInfo> QueryServerAsync(string ip, string queryDomain)
    {
        var (host, port) = ParseServerEndpoint(ip);
        var addressFamily = System.Net.IPAddress.TryParse(host, out var parsedAddress)
            ? parsedAddress.AddressFamily
            : AddressFamily.InterNetwork;

        using var udp = new UdpClient(addressFamily);
        var id = Helpers.DnsQueryIdGenerator.NextUShort();
        byte[] cookie = new byte[8];
        try {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(cookie);
        } catch { /* best-effort */ }
        var query = BuildQuery(queryDomain, id, cookie);
        using var udpCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await udp.SendAsync(query, query.Length, host, port).WaitWithCancellation(udpCts.Token);
        var resp = await udp.ReceiveAsync().WaitWithCancellation(udpCts.Token);
        var data = resp.Buffer;
        bool truncated = data.Length > 2 && (data[2] & 0x02) != 0;        
        if (truncated)
        {
            using var tcp = parsedAddress != null
                ? new TcpClient(parsedAddress.AddressFamily)
                : new TcpClient();
            using var tcpCts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            await tcp.ConnectAsync(host, port).WaitWithCancellation(tcpCts.Token);
            using var stream = tcp.GetStream();
            var len = (ushort)query.Length;
            var prefix = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };
            await stream.WriteAsync(prefix, 0, 2, tcpCts.Token);
            await stream.WriteAsync(query, 0, query.Length, tcpCts.Token);
            await stream.FlushAsync(tcpCts.Token);
            var buf = new byte[2];
            if (await ReadExactAsync(stream, buf, 0, 2, tcpCts.Token) != 2)
            {
                return new EdnsSupportInfo { Supported = false };
            }
            int respLen = buf[0] << 8 | buf[1];
            var respData = new byte[respLen];
            int received = 0;
            while (received < respLen)
            {
                var r = await stream.ReadAsync(respData, received, respLen - received, tcpCts.Token);
                if (r == 0)
                {
                    break;
                }
                received += r;
            }
            if (received < respLen)
            {
                return new EdnsSupportInfo { Supported = false };
            }
            data = respData;
        }

        var info = ParseEdns(data, cookie);
        // Map truncation hint
        return info with { TruncatedUdp = truncated };
    }

    /// <summary>
    /// Queries authoritative servers to determine EDNS support.
    /// </summary>
    /// <param name="domainName">Domain name.</param>
    /// <param name="logger">Optional logger.</param>
    public async Task Analyze(string domainName, InternalLogger logger)
    {
        Subject = domainName;
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "EDNS", target: domainName);
        ServerSupport.Clear();
        var ns = await QueryDns(domainName, DnsRecordType.NS);
        foreach (var record in ns)
        {
            var host = record.Data.Trim('.');
            var aTask = QueryDns(host, DnsRecordType.A);
            var aaaaTask = QueryDns(host, DnsRecordType.AAAA);
            try
            {
                await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);
            }
            catch
            {
                // Preserve whichever address family succeeded so EDNS probing can continue.
            }

            if (aTask.IsFaulted)
            {
                logger?.WriteWarning("Failed to resolve A records for {0}: {1}", host, aTask.Exception?.GetBaseException().Message ?? "unknown error");
            }

            if (aaaaTask.IsFaulted)
            {
                logger?.WriteWarning("Failed to resolve AAAA records for {0}: {1}", host, aaaaTask.Exception?.GetBaseException().Message ?? "unknown error");
            }

            var aRecords = aTask.Status == TaskStatus.RanToCompletion ? aTask.Result : Array.Empty<DnsAnswer>();
            var aaaaRecords = aaaaTask.Status == TaskStatus.RanToCompletion ? aaaaTask.Result : Array.Empty<DnsAnswer>();
            var addresses = aRecords
                .Concat(aaaaRecords)
                .Select(addr => addr.Data ?? addr.DataRaw)
                .Where(serverAddress => !string.IsNullOrWhiteSpace(serverAddress))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            foreach (var serverAddress in addresses)
            {
                EdnsSupportInfo support;
                if (QueryServerOverride != null)
                {
                    support = await QueryServerOverride(serverAddress);
                }
                else
                {
                    support = await QueryServerAsync(serverAddress, domainName);
                }

                ServerSupport[$"{host} ({serverAddress})"] = support;
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
    }

    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
}
