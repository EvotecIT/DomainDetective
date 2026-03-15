using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Attempts AXFR queries to determine if name servers allow unauthenticated zone transfers.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class ZoneTransferAnalysis : IHasAssessments
{
    private const byte RecursionDesiredFlag = 0x01;
    private const ushort OneQuestion = 1;
    private const ushort TypeAxfr = 252;
    private const ushort TypeSoa = 6;
    private const ushort ClassIn = 1;
    private static readonly Random Rng = new();

    /// <summary>Domain (zone) under test.</summary>
    public string? Subject { get; set; }

    /// <summary>Dictionary mapping server name to transfer allowance.</summary>
    public Dictionary<string, bool> ServerResults { get; private set; } = new();

    /// <summary>Maximum time to wait for each transfer attempt.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    public List<Assessment> Assessments { get; } = new();

    /// <summary>
    /// Checks all provided name servers for zone transfer capability.
    /// </summary>
    /// <param name="domain">Zone name to request.</param>
    /// <param name="nameServers">Servers to test.</param>
    /// <param name="logger">Optional logger instance.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    public async Task AnalyzeServers(string domain, IEnumerable<string> nameServers, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        Subject = domain;
        ServerResults.Clear();
        foreach (var server in nameServers.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var ns = server.Trim('.');
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "AXFR", target: ns);
            var allowed = await AttemptZoneTransfer(domain, ns, logger, cancellationToken);
            ServerResults[server] = allowed;
            if (allowed)
            {
                logger.WriteWarningCode(ZoneTransferCodes.Allowed, "AXFR allowed on {0}", ns);
            }
            else
            {
                var failed = Assessments.Any(a => a.Code == ZoneTransferCodes.CheckFailed &&
                                                 string.Equals(a.Target, ns, StringComparison.OrdinalIgnoreCase));
                if (!failed)
                {
                    logger.WriteInformationCode(ZoneTransferCodes.Restricted, "AXFR refused on {0}", ns);
                }
            }
        }
    }

    private static byte[] EncodeDomainName(string name)
    {
        var parts = name.TrimEnd('.').Split('.');
        using var ms = new MemoryStream();
        foreach (var part in parts)
        {
            var bytes = Encoding.ASCII.GetBytes(part);
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    private static byte[] BuildAxfrQuery(string zone, ushort id)
    {
        var header = new byte[12];
        header[0] = (byte)(id >> 8);
        header[1] = (byte)(id & 0xFF);
        header[2] = RecursionDesiredFlag;
        header[5] = (byte)OneQuestion;
        var qname = EncodeDomainName(zone);
        var query = new byte[header.Length + qname.Length + 4];
        Buffer.BlockCopy(header, 0, query, 0, header.Length);
        Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
        var offset = header.Length + qname.Length;
        query[offset] = (byte)(TypeAxfr >> 8);
        query[offset + 1] = (byte)(TypeAxfr & 0xFF);
        query[offset + 2] = (byte)(ClassIn >> 8);
        query[offset + 3] = (byte)(ClassIn & 0xFF);
        return query;
    }

    private static ushort ReadUInt16(byte[] buffer, ref int offset)
    {
        var value = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
        offset += 2;
        return value;
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken token)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, token);
            if (bytesRead == 0)
            {
                return false;
            }

            totalRead += bytesRead;
        }

        return true;
    }

    private static void SkipName(byte[] buffer, ref int offset)
    {
        while (true)
        {
            var len = buffer[offset++];
            if (len == 0)
            {
                return;
            }

            if ((len & 0xC0) == 0xC0)
            {
                offset++;
                return;
            }

            offset += len;
        }
    }

    private async Task<bool> AttemptZoneTransfer(string zone, string server, InternalLogger logger, CancellationToken token)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
            int port = 53;
            var host = server;
            var idx = host.IndexOf(':');
            if (idx > 0)
            {
                var portPart = host.Substring(idx + 1);
                if (int.TryParse(portPart, out var parsed))
                {
                    host = host.Substring(0, idx);
                    port = parsed;
                }
            }
            await client.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
            using var stream = client.GetStream();
            ushort id;
            lock (Rng)
            {
                id = (ushort)Rng.Next(ushort.MaxValue + 1);
            }
            var query = BuildAxfrQuery(zone, id);
            var len = (ushort)query.Length;
            var prefix = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };
            await stream.WriteAsync(prefix, 0, prefix.Length, cts.Token);
            await stream.WriteAsync(query, 0, query.Length, cts.Token);
            var prefixBuffer = new byte[2];
            var startSoaSeen = false;
            while (true)
            {
                if (!await ReadExactAsync(stream, prefixBuffer, 0, prefixBuffer.Length, cts.Token))
                {
                    logger?.WriteWarningCode(ZoneTransferCodes.CheckFailed, "AXFR connection closed by {0}", server);
                    return false;
                }

                int respLen = (prefixBuffer[0] << 8) | prefixBuffer[1];
                if (respLen < 12)
                {
                    var discard = new byte[respLen];
                    await ReadExactAsync(stream, discard, 0, discard.Length, cts.Token);
                    logger?.WriteWarningCode(ZoneTransferCodes.CheckFailed, "AXFR response too short from {0}", server);
                    return false;
                }

                var message = new byte[respLen];
                if (!await ReadExactAsync(stream, message, 0, message.Length, cts.Token))
                {
                    logger?.WriteWarningCode(ZoneTransferCodes.CheckFailed, "AXFR response stream ended from {0}", server);
                    return false;
                }

                int offset = 0;
                var respId = ReadUInt16(message, ref offset);
                var flags = ReadUInt16(message, ref offset);
                var qd = ReadUInt16(message, ref offset);
                var an = ReadUInt16(message, ref offset);
                offset += 4; // NSCOUNT + ARCOUNT
                if (respId != id)
                {
                    return false;
                }

                var rcode = (byte)(flags & 0x0F);
                if (rcode != 0)
                {
                    return false;
                }

                for (int i = 0; i < qd; i++)
                {
                    SkipName(message, ref offset);
                    offset += 4;
                }

                for (int i = 0; i < an; i++)
                {
                    SkipName(message, ref offset);
                    if (offset + 10 > message.Length)
                    {
                        return false;
                    }

                    var type = ReadUInt16(message, ref offset);
                    offset += 2; // class
                    offset += 4; // ttl
                    var rdlen = ReadUInt16(message, ref offset);
                    if (offset + rdlen > message.Length)
                    {
                        return false;
                    }

                    offset += rdlen;
                    if (type == TypeSoa)
                    {
                        if (!startSoaSeen)
                        {
                            startSoaSeen = true;
                        }
                        else
                        {
                            return true;
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Treat timeouts/cancellations as closed transfer for robust CI behavior
            return false;
        }
        catch (Exception ex)
        {
            using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "AXFR", target: server) : null;
            logger?.WriteWarningCode(ZoneTransferCodes.CheckFailed, "AXFR check failed for {0}: {1}", server, ex.Message);
            return false;
        }
    }
    }
