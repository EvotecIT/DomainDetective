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
public class EdnsSupportAnalysis
{
    /// <summary>EDNS support results keyed by server.</summary>
    public Dictionary<string, bool> ServerSupport { get; private set; } = new();

    public DnsConfiguration DnsConfiguration { get; set; } = new();
    public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
    public Func<string, Task<bool>>? QueryServerOverride { private get; set; }

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

    private static bool HasOptRecord(byte[] data)
    {
        for (int i = 0; i < data.Length - 2; i++)
        {
            if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x29)
            {
                return true;
            }
        }
        return false;
    }

    private static async Task<bool> QueryServerAsync(string ip)
    {
        using var udp = new UdpClient();
        var id = (ushort)new Random().Next(ushort.MaxValue);
        var query = BuildQuery("example.com", id);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
#if NET8_0_OR_GREATER
        await udp.SendAsync(query, ip, 53, cts.Token);
        var resp = await udp.ReceiveAsync(cts.Token);
#else
        await udp.SendAsync(query, query.Length, ip, 53).WaitWithCancellation(cts.Token);
        var resp = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
        return HasOptRecord(resp.Buffer);
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
                bool support;
                if (QueryServerOverride != null)
                {
                    support = await QueryServerOverride(addr.Data);
                }
                else
                {
                    support = await QueryServerAsync(addr.Data);
                }

                ServerSupport[$"{host} ({addr.Data})"] = support;
                logger?.WriteVerbose("EDNS support for {0} ({1}): {2}", host, addr.Data, support);
            }
        }
    }
}
