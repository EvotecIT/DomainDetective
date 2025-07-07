using DnsClientX;
using System;
using System.Collections.Generic;
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
}

/// <summary>
/// Performs EDNS capability checks against authoritative servers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class EdnsSupportAnalysis
{
    /// <summary>EDNS support results keyed by server.</summary>
    public Dictionary<string, EdnsSupportInfo> ServerSupport { get; private set; } = new();

    /// <summary>Configuration for DNS queries.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new();

    /// <summary>Allows overriding DNS queries for testing.</summary>
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

    /// <summary>Allows overriding server queries for testing.</summary>
    public Func<string, Task<EdnsSupportInfo>>? QueryServerOverride { private get; set; }

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

    private static byte[] BuildQuery(string domain, ushort id)
    {
        var qname = EncodeDomainName(domain);
        var query = new byte[12 + qname.Length + 4 + 11];
        query[0] = (byte)(id >> 8);
        query[1] = (byte)id;
        query[2] = 0x01;
        query[5] = 0x01; // qdcount
        Buffer.BlockCopy(qname, 0, query, 12, qname.Length);
        var offset = 12 + qname.Length;
        query[offset] = 0x00;
        query[offset + 1] = 0x01;
        query[offset + 2] = 0x00;
        query[offset + 3] = 0x01;
        offset += 4;
        // OPT record
        query[10] = 0x00;
        query[11] = 0x01; // arcount
        query[offset] = 0x00;
        query[offset + 1] = 0x00;
        query[offset + 2] = 0x29;
        query[offset + 3] = 0x10;
        query[offset + 4] = 0x00;
        query[offset + 5] = 0x00;
        query[offset + 6] = 0x00;
        query[offset + 7] = 0x00;
        query[offset + 8] = 0x00;
        query[offset + 9] = 0x00;
        query[offset + 10] = 0x00;
        return query;
    }

    private static EdnsSupportInfo ParseEdns(byte[] data)
    {
        for (int i = 0; i < data.Length - 10; i++)
        {
            if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x29)
            {
                int udpPayload = data[i + 3] << 8 | data[i + 4];
                int flags = data[i + 7] << 8 | data[i + 8];
                bool doBit = (flags & 0x8000) != 0;
                return new EdnsSupportInfo
                {
                    Supported = true,
                    UdpPayloadSize = udpPayload,
                    DoBit = doBit
                };
            }
        }

        return new EdnsSupportInfo { Supported = false, UdpPayloadSize = 0, DoBit = false };
    }

    private static async Task<EdnsSupportInfo> QueryServerAsync(string ip)
    {
        int port = 53;
        var host = ip;
        var idx = host.IndexOf(':');
        if (idx > 0 && int.TryParse(host.Substring(idx + 1), out var parsed))
        {
            host = host.Substring(0, idx);
            port = parsed;
        }

        using var udp = new UdpClient();
        var id = (ushort)new Random().Next(ushort.MaxValue);
        var query = BuildQuery("example.com", id);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
#if NET8_0_OR_GREATER
        await udp.SendAsync(query, host, port, cts.Token);
        var resp = await udp.ReceiveAsync(cts.Token);
#else
        await udp.SendAsync(query, query.Length, host, port).WaitWithCancellation(cts.Token);
        var resp = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
        var data = resp.Buffer;
        bool truncated = data.Length > 2 && (data[2] & 0x02) != 0;
        if (truncated)
        {
            using var tcp = new TcpClient();
#if NET6_0_OR_GREATER
            await tcp.ConnectAsync(host, port, cts.Token);
#else
            await tcp.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
#endif
            using var stream = tcp.GetStream();
            var len = (ushort)query.Length;
            var prefix = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };
#if NET8_0_OR_GREATER
            await stream.WriteAsync(prefix, cts.Token);
            await stream.WriteAsync(query, cts.Token);
            await stream.FlushAsync(cts.Token);
            var buf = new byte[2];
            if (await stream.ReadAsync(buf, cts.Token) != 2)
            {
                return new EdnsSupportInfo { Supported = false };
            }
#else
            await stream.WriteAsync(prefix, 0, 2, cts.Token);
            await stream.WriteAsync(query, 0, query.Length, cts.Token);
            await stream.FlushAsync(cts.Token);
            var buf = new byte[2];
            if (await stream.ReadAsync(buf, 0, 2, cts.Token) != 2)
            {
                return new EdnsSupportInfo { Supported = false };
            }
#endif
            int respLen = buf[0] << 8 | buf[1];
            var respData = new byte[respLen];
            int received = 0;
            while (received < respLen)
            {
#if NET8_0_OR_GREATER
                var r = await stream.ReadAsync(respData.AsMemory(received, respLen - received), cts.Token);
#else
                var r = await stream.ReadAsync(respData, received, respLen - received, cts.Token);
#endif
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

        return ParseEdns(data);
    }

    /// <summary>
    /// Queries authoritative servers to determine EDNS support.
    /// </summary>
    /// <param name="domainName">Domain name.</param>
    /// <param name="logger">Optional logger.</param>
    public async Task Analyze(string domainName, InternalLogger logger)
    {
        ServerSupport.Clear();
        var ns = await QueryDns(domainName, DnsRecordType.NS);
        foreach (var record in ns)
        {
            var host = record.Data.Trim('.');
            var a = await QueryDns(host, DnsRecordType.A);
            foreach (var addr in a)
            {
                EdnsSupportInfo support;
                if (QueryServerOverride != null)
                {
                    support = await QueryServerOverride(addr.Data);
                }
                else
                {
                    support = await QueryServerAsync(addr.Data);
                }

                ServerSupport[$"{host} ({addr.Data})"] = support;
                logger?.WriteVerbose("EDNS support for {0} ({1}): {2}", host, addr.Data, support.Supported);
            }
        }
    }
}
