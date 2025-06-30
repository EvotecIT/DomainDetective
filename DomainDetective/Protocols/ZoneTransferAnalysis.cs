using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Attempts AXFR queries to determine if name servers allow unauthenticated zone transfers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class ZoneTransferAnalysis {
        /// <summary>Dictionary mapping server name to transfer allowance.</summary>
        public Dictionary<string, bool> ServerResults { get; private set; } = new();

        /// <summary>Maximum time to wait for each transfer attempt.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Checks all provided name servers for zone transfer capability.
        /// </summary>
        /// <param name="domain">Zone name to request.</param>
        /// <param name="nameServers">Servers to test.</param>
        /// <param name="logger">Optional logger instance.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeServers(string domain, IEnumerable<string> nameServers, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var server in nameServers.Where(s => !string.IsNullOrWhiteSpace(s))) {
                cancellationToken.ThrowIfCancellationRequested();
                var allowed = await AttemptZoneTransfer(domain, server.Trim('.'), logger, cancellationToken);
                ServerResults[server] = allowed;
            }
        }

        private static byte[] EncodeDomainName(string name) {
            var parts = name.TrimEnd('.').Split('.');
            using var ms = new MemoryStream();
            foreach (var part in parts) {
                var bytes = Encoding.ASCII.GetBytes(part);
                ms.WriteByte((byte)bytes.Length);
                ms.Write(bytes, 0, bytes.Length);
            }
            ms.WriteByte(0);
            return ms.ToArray();
        }

        private static byte[] BuildAxfrQuery(string zone, ushort id) {
            var header = new byte[12];
            header[0] = (byte)(id >> 8);
            header[1] = (byte)(id & 0xFF);
            header[2] = 0x01; // recursion desired
            header[5] = 0x01; // one question
            var qname = EncodeDomainName(zone);
            var query = new byte[header.Length + qname.Length + 4];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
            var offset = header.Length + qname.Length;
            query[offset] = 0x00;
            query[offset + 1] = 0xFC; // AXFR
            query[offset + 2] = 0x00;
            query[offset + 3] = 0x01; // IN class
            return query;
        }

        private static ushort ReadUInt16(byte[] buffer, ref int offset) {
            var value = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;
            return value;
        }

        private static void SkipName(byte[] buffer, ref int offset) {
            while (true) {
                var len = buffer[offset++];
                if (len == 0) { return; }
                if ((len & 0xC0) == 0xC0) {
                    offset++;
                    return;
                }
                offset += len;
            }
        }

        private async Task<bool> AttemptZoneTransfer(string zone, string server, InternalLogger logger, CancellationToken token) {
            try {
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(Timeout);
#if NET8_0_OR_GREATER
                int port = 53;
                var host = server;
#else
                int port = 53;
                var host = server;
#endif
                var idx = host.IndexOf(':');
                if (idx > 0) {
                    var portPart = host.Substring(idx + 1);
                    if (int.TryParse(portPart, out var parsed)) {
                        host = host.Substring(0, idx);
                        port = parsed;
                    }
                }
#if NET8_0_OR_GREATER
                await client.ConnectAsync(host, port, cts.Token);
#else
                await client.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
#endif
                using var stream = client.GetStream();
                var id = (ushort)new Random().Next(ushort.MaxValue);
                var query = BuildAxfrQuery(zone, id);
                var len = (ushort)query.Length;
                var prefix = new byte[] { (byte)(len >> 8), (byte)(len & 0xFF) };
#if NET8_0_OR_GREATER
                await stream.WriteAsync(prefix, cts.Token);
                await stream.WriteAsync(query, cts.Token);
#else
                await stream.WriteAsync(prefix, 0, 2, cts.Token);
                await stream.WriteAsync(query, 0, query.Length, cts.Token);
#endif
                var prefixBuffer = new byte[2];
                var startSoaSeen = false;
                while (true) {
#if NET8_0_OR_GREATER
                    int read = await stream.ReadAsync(prefixBuffer, cts.Token);
#else
                    int read = await stream.ReadAsync(prefixBuffer, 0, 2, cts.Token);
#endif
                    if (read == 0) { return false; }
                    if (read != 2) { return false; }

                    int respLen = (prefixBuffer[0] << 8) | prefixBuffer[1];
                    if (respLen < 12) {
                        await stream.ReadAsync(new byte[respLen], 0, respLen, cts.Token);
                        return false;
                    }

                    var message = new byte[respLen];
                    int received = 0;
                    while (received < respLen) {
#if NET8_0_OR_GREATER
                        var r = await stream.ReadAsync(message.AsMemory(received, respLen - received), cts.Token);
#else
                        var r = await stream.ReadAsync(message, received, respLen - received, cts.Token);
#endif
                        if (r == 0) { return false; }
                        received += r;
                    }

                    int offset = 0;
                    var respId = ReadUInt16(message, ref offset);
                    var flags = ReadUInt16(message, ref offset);
                    var qd = ReadUInt16(message, ref offset);
                    var an = ReadUInt16(message, ref offset);
                    offset += 4; // NSCOUNT + ARCOUNT
                    if (respId != id) { return false; }
                    var rcode = (byte)(flags & 0x0F);
                    if (rcode != 0) { return false; }

                    for (int i = 0; i < qd; i++) {
                        SkipName(message, ref offset);
                        offset += 4;
                    }

                    for (int i = 0; i < an; i++) {
                        SkipName(message, ref offset);
                        if (offset + 10 > message.Length) { return false; }
                        var type = ReadUInt16(message, ref offset);
                        offset += 2; // class
                        offset += 4; // ttl
                        var rdlen = ReadUInt16(message, ref offset);
                        if (offset + rdlen > message.Length) { return false; }
                        offset += rdlen;
                        if (type == 6) {
                            if (!startSoaSeen) {
                                startSoaSeen = true;
                            } else {
                                return true;
                            }
                        }
                    }
                }
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteVerbose("AXFR check failed for {0}: {1}", server, ex.Message);
                return false;
            }
        }
    }
}
