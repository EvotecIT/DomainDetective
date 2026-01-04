using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs targeted DNS health checks that require querying authoritative servers directly
    /// (SOA serial skew and apex A/AAAA consistency across NS).
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsHealthAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        public Func<IPAddress, byte[], CancellationToken, Task<byte[]?>>? QueryUdpOverride { get; set; }

        public List<string> NameServers { get; private set; } = new();
        public Dictionary<string, long> SoaSerialByServer { get; } = new();
        public bool SoaSerialConsistent { get; private set; }

        public Dictionary<string, List<string>> ApexAddressesByServer { get; } = new();
        public bool ApexAddressesConsistent { get; private set; }

        public bool ServersResponsive { get; private set; }

        public List<Assessment> Assessments { get; } = new();

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            return await DnsConfiguration.QueryDNS(name, type);
        }

        public async Task Analyze(string domainName, InternalLogger logger, CancellationToken cancellationToken = default) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNSHEALTH", target: domainName);
            Subject = domainName;
            NameServers.Clear();
            SoaSerialByServer.Clear();
            ApexAddressesByServer.Clear();
            SoaSerialConsistent = true;
            ApexAddressesConsistent = true;
            ServersResponsive = true;

            // Discover NS hostnames and their addresses
            var nsAnswers = await QueryDns(domainName, DnsRecordType.NS);
            var nsHosts = nsAnswers.Select(a => a.Data.Trim('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            NameServers.AddRange(nsHosts);
            var nsIps = new List<(string host, IPAddress ip)>();
            foreach (var ns in nsHosts) {
                cancellationToken.ThrowIfCancellationRequested();
                var a = await QueryDns(ns, DnsRecordType.A);
                foreach (var ans in a) {
                    if (IPAddress.TryParse(ans.Data, out var ip)) {
                        nsIps.Add((ns, ip));
                    }
                }
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA);
                foreach (var ans in aaaa) {
                    if (IPAddress.TryParse(ans.Data, out var ip6)) {
                        nsIps.Add((ns, ip6));
                    }
                }
            }

            if (nsIps.Count == 0) {
                return;
            }

            // Query SOA serial and apex A/AAAA directly from each server
            foreach (var (host, ip) in nsIps) {
                cancellationToken.ThrowIfCancellationRequested();
                var serverKey = ip.ToString();
                var serial = await QuerySoaSerial(ip, domainName, cancellationToken);
                if (serial.HasValue) {
                    SoaSerialByServer[serverKey] = serial.Value;
                }
                var apex = await QueryApexAddresses(ip, domainName, cancellationToken);
                if (apex.Count > 0) {
                    ApexAddressesByServer[serverKey] = apex;
                }
            }

            // Evaluate consistency
            if (SoaSerialByServer.Count > 1) {
                var first = SoaSerialByServer.First().Value;
                foreach (var kv in SoaSerialByServer) {
                    if (kv.Value != first) { SoaSerialConsistent = false; break; }
                }
            }

            if (!SoaSerialConsistent) {
                logger?.WriteWarningCode(DnsHealthCodes.SoaSerialSkew, "SOA serial numbers differ across authoritative servers");
            } else {
                logger?.WriteInformationCode(DnsHealthCodes.SoaSerialConsistent, "SOA serial numbers consistent across authoritative servers");
            }

            if (ApexAddressesByServer.Count > 1) {
                string Canonical(List<string> list) {
                    var arr = list.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    arr.Sort(StringComparer.OrdinalIgnoreCase);
                    return string.Join(",", arr);
                }
                string? baseline = null;
                foreach (var kv in ApexAddressesByServer) {
                    var canon = Canonical(kv.Value);
                    if (baseline == null) baseline = canon;
                    else if (!string.Equals(baseline, canon, StringComparison.OrdinalIgnoreCase)) { ApexAddressesConsistent = false; break; }
                }
            }

            if (!ApexAddressesConsistent) {
                logger?.WriteWarningCode(DnsHealthCodes.ApexInconsistent, "A/AAAA answers for zone apex differ across authoritative servers");
            }

            ServersResponsive = SoaSerialByServer.Count == nsIps.Count && ApexAddressesByServer.Count == nsIps.Count;
            if (ServersResponsive) {
                logger?.WriteInformationCode(DnsHealthCodes.ServersResponsive, "All authoritative name servers responded to queries");
            }
        }

        private static byte[] EncodeDomainName(string name, bool trailingDot) {
            var parts = name.TrimEnd('.').Split('.');
            using var ms = new System.IO.MemoryStream();
            foreach (var part in parts) {
                var bytes = System.Text.Encoding.ASCII.GetBytes(part);
                ms.WriteByte((byte)bytes.Length);
                ms.Write(bytes, 0, bytes.Length);
            }
            if (trailingDot) {
                ms.WriteByte(0);
            }
            return ms.ToArray();
        }

        private static byte[] BuildQuery(string domain, ushort qtype) {
            var header = new byte[12];
            var id = Helpers.DnsQueryIdGenerator.NextUShort();
            header[0] = (byte)(id >> 8);
            header[1] = (byte)(id & 0xFF);
            header[2] = 0x01; // RD
            header[5] = 0x01; // QDCOUNT
            var qname = EncodeDomainName(domain, true);
            var query = new byte[header.Length + qname.Length + 4];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
            var offset = header.Length + qname.Length;
            query[offset] = (byte)(qtype >> 8);
            query[offset + 1] = (byte)(qtype & 0xFF);
            query[offset + 2] = 0x00;
            query[offset + 3] = 0x01; // IN
            return query;
        }

        private static void SkipName(byte[] buffer, ref int offset) {
            int jumps = 0;
            while (true) {
                if (offset >= buffer.Length) { offset = buffer.Length; return; }
                var len = buffer[offset++];
                if (len == 0) break;
                if ((len & 0xC0) == 0xC0) { if (offset < buffer.Length) offset++; break; }
                offset += len;
                if (++jumps > 50) break;
            }
        }

        private static ushort ReadUInt16(byte[] buffer, ref int offset) {
            if (offset + 2 > buffer.Length) return 0;
            var val = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2; return val;
        }
        private static uint ReadUInt32(byte[] buffer, ref int offset) {
            if (offset + 4 > buffer.Length) return 0;
            var v = (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | (buffer[offset + 2] << 8) | buffer[offset + 3]);
            offset += 4; return v;
        }

        private async Task<byte[]?> QueryUdp(IPAddress server, byte[] query, CancellationToken token) {
            if (QueryUdpOverride != null) {
                return await QueryUdpOverride(server, query, token);
            }

            using var udp = new UdpClient(new IPEndPoint(server.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = 4000;
#if NET8_0_OR_GREATER
            await udp.SendAsync(query, new IPEndPoint(server, 53));
            var res = await udp.ReceiveAsync(token);
            return res.Buffer;
#else
            await udp.SendAsync(query, query.Length, new IPEndPoint(server, 53)).WaitWithCancellation(token);
            var res = await udp.ReceiveAsync().WaitWithCancellation(token);
            return res.Buffer;
#endif
        }

        private async Task<long?> QuerySoaSerial(IPAddress server, string zone, CancellationToken token) {
            try {
                var query = BuildQuery(zone, 6); // SOA
                var data = await QueryUdp(server, query, token);
                if (data == null || data.Length < 12) throw new InvalidOperationException();
                int offset = 0;
                offset += 4; // id+flags
                var qd = ReadUInt16(data, ref offset);
                var an = ReadUInt16(data, ref offset);
                offset += 4; // nscount + arcount
                for (int i = 0; i < qd; i++) { SkipName(data, ref offset); offset += 4; }
                for (int i = 0; i < an; i++) {
                    SkipName(data, ref offset);
                    var type = ReadUInt16(data, ref offset);
                    offset += 2; // class
                    offset += 4; // ttl
                    var rdlen = ReadUInt16(data, ref offset);
                    if (type == 6) {
                        // SOA RDATA
                        SkipName(data, ref offset); // MNAME
                        SkipName(data, ref offset); // RNAME
                        var serial = ReadUInt32(data, ref offset);
                        return serial;
                    }
                    offset += rdlen;
                }
            } catch { }
            try {
                var soa = await QueryDns(zone, DnsRecordType.SOA);
                if (soa != null && soa.Length > 0 && !string.IsNullOrWhiteSpace(soa[0].Data)) {
                    var parts = soa[0].Data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3 && long.TryParse(parts[2], out var serial)) return serial;
                }
            } catch { }
            return null;
        }

        private async Task<List<string>> QueryApexAddresses(IPAddress server, string zone, CancellationToken token) {
            var list = new List<string>();
            async Task Fetch(ushort qtype) {
                var query = BuildQuery(zone, qtype);
                var data = await QueryUdp(server, query, token);
                if (data == null || data.Length < 12) return;
                int offset = 0;
                offset += 4; // id+flags
                var qd = ReadUInt16(data, ref offset);
                var an = ReadUInt16(data, ref offset);
                offset += 4; // nscount + arcount
                for (int i = 0; i < qd; i++) { SkipName(data, ref offset); offset += 4; }
                for (int i = 0; i < an; i++) {
                    SkipName(data, ref offset);
                    var type = ReadUInt16(data, ref offset);
                    offset += 2; // class
                    offset += 4; // ttl
                    var rdlen = ReadUInt16(data, ref offset);
                    if (type == 1 && rdlen == 4) {
                        if (offset + 4 <= data.Length) {
                            var ip = new IPAddress(new byte[] { data[offset], data[offset + 1], data[offset + 2], data[offset + 3] });
                            list.Add(ip.ToString());
                        }
                    } else if (type == 28 && rdlen == 16) {
                        if (offset + 16 <= data.Length) {
                            var bytes = new byte[16];
                            Buffer.BlockCopy(data, offset, bytes, 0, 16);
                            list.Add(new IPAddress(bytes).ToString());
                        }
                    }
                    offset += rdlen;
                }
            }
            try { await Fetch(1); } catch { }
            try { await Fetch(28); } catch { }
            if (list.Count == 0) {
                try {
                    var a = await QueryDns(zone, DnsRecordType.A);
                    foreach (var ans in a) list.Add(ans.Data);
                    var aaaa = await QueryDns(zone, DnsRecordType.AAAA);
                    foreach (var ans in aaaa) list.Add(ans.Data);
                } catch { }
            }
            return list;
        }
    }
}
