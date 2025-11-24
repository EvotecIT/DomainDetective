using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Collects TTL values for common DNS records and exposes warnings
    /// when values fall outside recommended ranges.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Typical TTL thresholds are based on operational best practices and may
    /// be adjusted to suit specific environments.
    /// </remarks>
    public class DnsTtlAnalysis : IHasAssessments {
        private readonly List<string> _warnings = new();
        public string? Subject { get; set; }

        /// <summary>
        /// Indicates whether the zone is signed with DNSSEC.
        /// </summary>
        public bool DnsSecSigned { get; private set; }

        /// <summary>Gets TTL values for A records including zero values.</summary>
        public IReadOnlyList<int> ATtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for A records (queried from NS hosts).</summary>
        public IReadOnlyList<int> AuthoritativeATtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for AAAA records including zero values.</summary>
        public IReadOnlyList<int> AaaaTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for AAAA records.</summary>
        public IReadOnlyList<int> AuthoritativeAaaaTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for MX records including zero values.</summary>
        public IReadOnlyList<int> MxTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for MX records.</summary>
        public IReadOnlyList<int> AuthoritativeMxTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for NS records including zero values.</summary>
        public IReadOnlyList<int> NsTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for NS records.</summary>
        public IReadOnlyList<int> AuthoritativeNsTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets the TTL value for the SOA record; zero indicates no TTL or missing record.</summary>
        public int SoaTtl { get; private set; }
        /// <summary>Authoritative SOA TTL (queried directly from NS); null when unavailable.</summary>
        public int? AuthoritativeSoaTtl { get; private set; }
        /// <summary>TTL values for SPF TXT at the zone apex.</summary>
        public IReadOnlyList<int> SpfTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for SPF TXT at the zone apex.</summary>
        public IReadOnlyList<int> AuthoritativeSpfTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _dmarc TXT.</summary>
        public IReadOnlyList<int> DmarcTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for _dmarc TXT.</summary>
        public IReadOnlyList<int> AuthoritativeDmarcTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _mta-sts TXT records.</summary>
        public IReadOnlyList<int> MtastsTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for _mta-sts TXT records.</summary>
        public IReadOnlyList<int> AuthoritativeMtastsTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _smtp._tls TXT records.</summary>
        public IReadOnlyList<int> TlsRptTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Authoritative TTL values for _smtp._tls TXT records.</summary>
        public IReadOnlyList<int> AuthoritativeTlsRptTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for DKIM selector TXT records, keyed by FQDN (selector._domainkey.domain).</summary>
        public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; private set; } = new();
        /// <summary>Authoritative TTL values for DKIM selector TXT records.</summary>
        public Dictionary<string, IReadOnlyList<int>> AuthoritativeDkimTxtTtls { get; private set; } = new();
        /// <summary>Collection of warning messages produced during analysis.</summary>
        public IReadOnlyList<string> Warnings => _warnings;

        /// <summary>Structured assessments captured during TTL analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>Provides DNS query implementation details.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();
        /// <summary>Optional list of DKIM selectors discovered earlier (used for TXT TTL checks).</summary>
        public List<string> DkimSelectors { get; set; } = new();
        /// <summary>Minimum TTL for SPF TXT records (seconds).</summary>
        public int MinTtlSpfSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for DMARC TXT records (seconds).</summary>
        public int MinTtlDmarcSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for MTA-STS TXT records (seconds).</summary>
        public int MinTtlMtastsSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for TLS-RPT TXT records (seconds).</summary>
        public int MinTtlTlsRptSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for DKIM selector TXT records (seconds).</summary>
        public int MinTtlDkimSelectorSeconds { get; set; } = 3600;

        // Per-authoritative-server TTL uniformity results
        public Dictionary<string, int?> ServerTtlA { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlAaaa { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlNs { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlCname { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlTxtSpf { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlTxtDmarc { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlMx { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlTxtMtasts { get; private set; } = new();
        public Dictionary<string, int?> ServerTtlTxtTlsRpt { get; private set; } = new();
        /// <summary>Per-name TXT TTLs across authoritative servers. Key is the record name (e.g., s1._domainkey.example.com).</summary>
        public Dictionary<string, Dictionary<string, int?>> ServerTtlTxtPerName { get; private set; } = new();
        public bool AUniformAcrossServers { get; private set; }
        public bool AaaaUniformAcrossServers { get; private set; }
        public bool NsUniformAcrossServers { get; private set; }
        public bool CnameUniformAcrossServers { get; private set; }

        /// <summary>
        /// Optional override for DNS queries, primarily used for testing.
        /// </summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>
        /// When true, queries authoritative name servers to collect configured TTL values alongside observed TTLs.
        /// </summary>
        public bool CollectAuthoritativeTtls { get; set; }

        private static IReadOnlyList<int> ExtractTxtTtls(IEnumerable<DnsAnswer> answers, string marker)
        {
            return answers
                .Where(r => r.Type == DnsRecordType.TXT && (r.Data ?? r.DataRaw ?? string.Empty).IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();
        }

        private async Task<IReadOnlyList<int>> QueryTxtTtlsWithAlias(string name, string marker)
        {
            var answers = await QueryDns(name, DnsRecordType.TXT);
            var ttls = ExtractTxtTtls(answers, marker);
            if (ttls.Count > 0)
            {
                return ttls;
            }

            var cnameTargets = answers
                .Where(r => r.Type == DnsRecordType.CNAME && !string.IsNullOrWhiteSpace(r.Data))
                .Select(r => r.Data!.Trim('.'))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            foreach (var target in cnameTargets)
            {
                try
                {
                    var follow = await QueryDns(target, DnsRecordType.TXT);
                    var followTtls = ExtractTxtTtls(follow, marker);
                    if (followTtls.Count > 0)
                    {
                        return followTtls;
                    }
                }
                catch { }
            }

            return Array.Empty<int>();
        }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        // Raw DNS helpers used to query authoritative servers directly
        private static byte[] EncodeDomainName(string name, bool trailingDot) {
            var parts = name.TrimEnd('.').Split('.');
            using var ms = new System.IO.MemoryStream();
            foreach (var part in parts) {
                var bytes = System.Text.Encoding.ASCII.GetBytes(part);
                ms.WriteByte((byte)bytes.Length);
                ms.Write(bytes, 0, bytes.Length);
            }
            if (trailingDot) ms.WriteByte(0);
            return ms.ToArray();
        }
        private static byte[] BuildQuery(string domain, ushort qtype, bool recursionDesired = true) {
            var header = new byte[12];
            var id = (ushort)new Random().Next(ushort.MaxValue);
            header[0] = (byte)(id >> 8); header[1] = (byte)(id & 0xFF);
            header[2] = recursionDesired ? (byte)0x01 : (byte)0x00; // RD flag
            header[5] = 0x01;
            var qname = EncodeDomainName(domain, true);
            var query = new byte[header.Length + qname.Length + 4];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
            var offset = header.Length + qname.Length;
            query[offset] = (byte)(qtype >> 8); query[offset + 1] = (byte)(qtype & 0xFF);
            query[offset + 2] = 0x00; query[offset + 3] = 0x01;
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
            var v = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2; return v;
        }
        private static async Task<byte[]?> QueryUdp(System.Net.IPAddress server, byte[] query, System.Threading.CancellationToken token) {
            using var udp = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(server.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? System.Net.IPAddress.IPv6Any : System.Net.IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = 4000;
#if NET6_0_OR_GREATER
            await udp.SendAsync(query, new System.Net.IPEndPoint(server, 53));
            var res = await udp.ReceiveAsync(token);
            return res.Buffer;
#else
            await udp.SendAsync(query, query.Length, new System.Net.IPEndPoint(server, 53)).WaitWithCancellation(token);
            var res = await udp.ReceiveAsync().WaitWithCancellation(token);
            return res.Buffer;
#endif
        }
        private static int? ParseFirstAnswerTtl(byte[] data, ushort qtype) {
            if (data == null || data.Length < 12) return null;
            int offset = 0;
            offset += 4; // id+flags
            var qd = ReadUInt16(data, ref offset);
            var an = ReadUInt16(data, ref offset);
            offset += 4; // nscount + arcount
            for (int i = 0; i < qd; i++) { SkipName(data, ref offset); offset += 4; }
            int? cnameTtl = null;
            for (int i = 0; i < an; i++) {
                SkipName(data, ref offset);
                var type = ReadUInt16(data, ref offset);
                offset += 2; // class
                var ttl = (offset + 4 <= data.Length) ? (int)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]) : 0;
                offset += 4;
                var rdlen = ReadUInt16(data, ref offset);
                if (type == qtype) return ttl;
                // For TXT queries, capture CNAME TTL as fallback (aliased records)
                if (qtype == 16 && type == 5 && !cnameTtl.HasValue) cnameTtl = ttl;
                offset += rdlen;
            }
            // If querying TXT and got CNAME but no TXT, return the CNAME TTL
            // This handles aliased SPF/DMARC records
            return cnameTtl;
        }
        private async Task<int?> QueryTtlFromServer(System.Net.IPAddress ip, string name, ushort qtype, System.Threading.CancellationToken ct) {
            // Prefer non-recursive queries to capture configured TTLs directly from authoritative servers.
            var q = BuildQuery(name, qtype, recursionDesired: false);
            var buf = await QueryUdp(ip, q, ct);
            var ttl = buf != null ? ParseFirstAnswerTtl(buf, qtype) : null;
            if (ttl.HasValue) return ttl;

            // Fallback to recursive queries when no direct answer is returned (e.g., CNAME chains).
            q = BuildQuery(name, qtype, recursionDesired: true);
            buf = await QueryUdp(ip, q, ct);
            return buf != null ? ParseFirstAnswerTtl(buf, qtype) : null;
        }

        /// <summary>
        /// Queries DNS records for TTL values and evaluates them.
        /// </summary>
        /// <param name="domainName">Domain name to analyze.</param>
        /// <param name="logger">Optional logger used for diagnostics.</param>
        public async Task Analyze(string domainName, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "DNS", target: domainName);
            Subject = domainName;
            _warnings.Clear();
            ATtls = Array.Empty<int>();
            AuthoritativeATtls = Array.Empty<int>();
            AaaaTtls = Array.Empty<int>();
            AuthoritativeAaaaTtls = Array.Empty<int>();
            MxTtls = Array.Empty<int>();
            AuthoritativeMxTtls = Array.Empty<int>();
            NsTtls = Array.Empty<int>();
            AuthoritativeNsTtls = Array.Empty<int>();
            SoaTtl = 0;
            AuthoritativeSoaTtl = null;
            SpfTxtTtls = Array.Empty<int>();
            AuthoritativeSpfTxtTtls = Array.Empty<int>();
            DmarcTxtTtls = Array.Empty<int>();
            AuthoritativeDmarcTxtTtls = Array.Empty<int>();
            MtastsTxtTtls = Array.Empty<int>();
            AuthoritativeMtastsTxtTtls = Array.Empty<int>();
            TlsRptTxtTtls = Array.Empty<int>();
            AuthoritativeTlsRptTxtTtls = Array.Empty<int>();
            DkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>();
            AuthoritativeDkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>();

            var aRecords = await QueryDns(domainName, DnsRecordType.A);
            var aaaaRecords = await QueryDns(domainName, DnsRecordType.AAAA);
            var mxRecords = await QueryDns(domainName, DnsRecordType.MX);
            var nsRecords = await QueryDns(domainName, DnsRecordType.NS);
            var soaRecords = await QueryDns(domainName, DnsRecordType.SOA);
            var dsRecords = await QueryDns(domainName, DnsRecordType.DS);
            var txtApex = await QueryDns(domainName, DnsRecordType.TXT);
            var txtDmarc = await QueryTxtTtlsWithAlias($"_dmarc.{domainName}", "v=DMARC1");
            var txtMtasts = await QueryTxtTtlsWithAlias($"_mta-sts.{domainName}", "v=STSv1");
            var txtTlsRpt = await QueryTxtTtlsWithAlias($"_smtp._tls.{domainName}", "v=TLSRPTv1");

            DnsSecSigned = dsRecords.Length > 0;

            ATtls = aRecords.Select(r => r.TTL).ToArray();
            AaaaTtls = aaaaRecords.Select(r => r.TTL).ToArray();
            MxTtls = mxRecords.Select(r => r.TTL).ToArray();
            NsTtls = nsRecords.Select(r => r.TTL).ToArray();
            SoaTtl = soaRecords.Length > 0 ? soaRecords[0].TTL : 0;

            // TXT TTLs
            SpfTxtTtls = txtApex
                .Where(r => (r.Data ?? string.Empty).IndexOf("v=spf1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();
            DmarcTxtTtls = txtDmarc.ToArray();
            MtastsTxtTtls = txtMtasts.ToArray();
            TlsRptTxtTtls = txtTlsRpt.ToArray();

            if (DkimSelectors != null && DkimSelectors.Count > 0)
            {
                foreach (var sel in DkimSelectors.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var name = $"{sel}._domainkey.{domainName}";
                    var dkimTxt = await QueryDns(name, DnsRecordType.TXT);
                    var list = dkimTxt.Select(r => r.TTL).ToArray();
                    DkimTxtTtls[name] = list;
                    // Evaluate per selector
                    Evaluate($"DKIM TXT ({sel})", list, MinTtlDkimSelectorSeconds, 86400, DnsSecSigned, logger);
                }
            }

            Evaluate("A", ATtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("AAAA", AaaaTtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("MX", MxTtls, 300, 86400, DnsSecSigned, logger);
            Evaluate("NS", NsTtls, 300, 86400, DnsSecSigned, logger);
            if (soaRecords.Length > 0) {
                Evaluate("SOA", new[] { SoaTtl }, 300, 86400, DnsSecSigned, logger);
            }

            // Evaluate TXT categories with specific minima
            if (SpfTxtTtls.Any()) Evaluate("SPF TXT", SpfTxtTtls, MinTtlSpfSeconds, 86400, false, logger);
            if (DmarcTxtTtls.Any()) Evaluate("DMARC TXT", DmarcTxtTtls, MinTtlDmarcSeconds, 86400, false, logger);
            if (MtastsTxtTtls.Any()) Evaluate("MTA-STS TXT", MtastsTxtTtls, MinTtlMtastsSeconds, 86400, false, logger);
            if (TlsRptTxtTtls.Any()) Evaluate("TLS-RPT TXT", TlsRptTxtTtls, MinTtlTlsRptSeconds, 86400, false, logger);
        }

        /// <summary>
        /// Compares TTLs across authoritative name servers for core RRsets (A, AAAA, NS, CNAME).
        /// </summary>
        public async Task AnalyzeUniformityAcrossServers(string domainName, InternalLogger logger, System.Threading.CancellationToken ct = default) {
            ServerTtlA = new(); ServerTtlAaaa = new(); ServerTtlNs = new(); ServerTtlCname = new();
            ServerTtlTxtSpf = new(); ServerTtlTxtDmarc = new(); ServerTtlTxtPerName = new();
            ServerTtlMx = new(); ServerTtlTxtMtasts = new(); ServerTtlTxtTlsRpt = new();
            AUniformAcrossServers = AaaaUniformAcrossServers = NsUniformAcrossServers = CnameUniformAcrossServers = true;
            var authoritativeSoa = CollectAuthoritativeTtls ? new List<int>() : null;

            // Discover authoritative NS hosts and IPs via resolver
            var nsAnswers = await QueryDns(domainName, DnsRecordType.NS);
            var nsHosts = nsAnswers.Select(a => a.Data?.Trim('.') ?? string.Empty).Where(h => !string.IsNullOrEmpty(h)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var nsIps = new List<System.Net.IPAddress>();
            foreach (var host in nsHosts) {
                var a = await QueryDns(host, DnsRecordType.A);
                foreach (var ans in a) if (System.Net.IPAddress.TryParse(ans.Data, out var ip)) nsIps.Add(ip);
                var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                foreach (var ans in aaaa) if (System.Net.IPAddress.TryParse(ans.Data, out var ip6)) nsIps.Add(ip6);
            }
            if (nsIps.Count == 0) return;

            foreach (var ip in nsIps) {
                ct.ThrowIfCancellationRequested();
                var key = ip.ToString();
                try { ServerTtlA[key] = await QueryTtlFromServer(ip, domainName, 1, ct); } catch { ServerTtlA[key] = null; }
                try { ServerTtlAaaa[key] = await QueryTtlFromServer(ip, domainName, 28, ct); } catch { ServerTtlAaaa[key] = null; }
                try { ServerTtlNs[key] = await QueryTtlFromServer(ip, domainName, 2, ct); } catch { ServerTtlNs[key] = null; }
                try { ServerTtlCname[key] = await QueryTtlFromServer(ip, domainName, 5, ct); } catch { ServerTtlCname[key] = null; }
                // TXT names: apex (SPF) and _dmarc
                try { ServerTtlTxtSpf[key] = await QueryTtlFromServer(ip, domainName, 16, ct); } catch { ServerTtlTxtSpf[key] = null; }
                try { ServerTtlTxtDmarc[key] = await QueryTtlFromServer(ip, $"_dmarc.{domainName}", 16, ct); } catch { ServerTtlTxtDmarc[key] = null; }
                if (CollectAuthoritativeTtls)
                {
                    try { var soa = await QueryTtlFromServer(ip, domainName, 6, ct); if (soa.HasValue) authoritativeSoa?.Add(soa.Value); } catch { }
                    try { ServerTtlMx[key] = await QueryTtlFromServer(ip, domainName, 15, ct); } catch { ServerTtlMx[key] = null; }
                    try { ServerTtlTxtMtasts[key] = await QueryTtlFromServer(ip, $"_mta-sts.{domainName}", 16, ct); } catch { ServerTtlTxtMtasts[key] = null; }
                    try { ServerTtlTxtTlsRpt[key] = await QueryTtlFromServer(ip, $"_smtp._tls.{domainName}", 16, ct); } catch { ServerTtlTxtTlsRpt[key] = null; }
                }
                // DKIM selectors
                if (DkimSelectors != null && DkimSelectors.Count > 0)
                {
                    foreach (var sel in DkimSelectors.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        var name = $"{sel}._domainkey.{domainName}";
                        if (!ServerTtlTxtPerName.TryGetValue(name, out var map)) { map = new(); ServerTtlTxtPerName[name] = map; }
                        try { map[key] = await QueryTtlFromServer(ip, name, 16, ct); } catch { map[key] = null; }
                    }
                }
            }

            static bool IsUniform(Dictionary<string, int?> map) {
                var vals = map.Values.Where(v => v.HasValue).Select(v => v!.Value).Distinct().ToArray();
                return vals.Length <= 1;
            }
            AUniformAcrossServers = IsUniform(ServerTtlA);
            AaaaUniformAcrossServers = IsUniform(ServerTtlAaaa);
            NsUniformAcrossServers = IsUniform(ServerTtlNs);
            CnameUniformAcrossServers = IsUniform(ServerTtlCname);

            if (!AUniformAcrossServers) {
                logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_A, "A TTL differs across authoritative name servers");
            } else {
                logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_A, "A TTL consistent across authoritative name servers.");
            }
            if (!AaaaUniformAcrossServers) {
                logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_AAAA, "AAAA TTL differs across authoritative name servers");
            } else {
                logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_AAAA, "AAAA TTL consistent across authoritative name servers.");
            }
            if (!NsUniformAcrossServers) {
                logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_NS, "NS TTL differs across authoritative name servers");
            } else {
                logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_NS, "NS TTL consistent across authoritative name servers.");
            }
            if (!CnameUniformAcrossServers) {
                logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_CNAME, "CNAME TTL differs across authoritative name servers");
            } else {
                logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_CNAME, "CNAME TTL consistent across authoritative name servers.");
            }

            // TXT apex (SPF)
            var txtSpfUniform = IsUniform(ServerTtlTxtSpf);
            if (!txtSpfUniform) logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_TXT_SPF, "SPF TXT TTL differs across authoritative name servers");
            else logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_TXT_SPF, "SPF TXT TTL consistent across authoritative name servers.");

            // TXT _dmarc
            var txtDmarcUniform = IsUniform(ServerTtlTxtDmarc);
            if (!txtDmarcUniform) logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_TXT_DMARC, "DMARC TXT TTL differs across authoritative name servers");
            else logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_TXT_DMARC, "DMARC TXT TTL consistent across authoritative name servers.");

            // DKIM selectors per name
            if (ServerTtlTxtPerName.Count > 0)
            {
                foreach (var kv in ServerTtlTxtPerName)
                {
                    var uniform = IsUniform(kv.Value);
                    if (!uniform) logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_TXT_DKIM, $"DKIM TXT TTL differs across authoritative servers for {kv.Key}");
                    else logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_TXT_DKIM, $"DKIM TXT TTL consistent across authoritative servers for {kv.Key}");
                }
            }

            if (CollectAuthoritativeTtls)
            {
                static IReadOnlyList<int> Aggregate(Dictionary<string, int?> map) =>
                    map.Values.Where(v => v.HasValue).Select(v => v!.Value).ToArray();

                AuthoritativeATtls = Aggregate(ServerTtlA);
                AuthoritativeAaaaTtls = Aggregate(ServerTtlAaaa);
                AuthoritativeNsTtls = Aggregate(ServerTtlNs);
                AuthoritativeMxTtls = Aggregate(ServerTtlMx);
                AuthoritativeSpfTxtTtls = Aggregate(ServerTtlTxtSpf);
                AuthoritativeDmarcTxtTtls = Aggregate(ServerTtlTxtDmarc);
                AuthoritativeMtastsTxtTtls = Aggregate(ServerTtlTxtMtasts);
                AuthoritativeTlsRptTxtTtls = Aggregate(ServerTtlTxtTlsRpt);
                AuthoritativeSoaTtl = authoritativeSoa?.Count > 0 ? authoritativeSoa.Min() : null;
                AuthoritativeDkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>(StringComparer.OrdinalIgnoreCase);
                foreach (var kv in ServerTtlTxtPerName)
                {
                    AuthoritativeDkimTxtTtls[kv.Key] = Aggregate(kv.Value);
                }
            }
        }

        private void Evaluate(string recordType, IEnumerable<int> ttls, int min, int max, bool dnssecSigned, InternalLogger logger) {
            var list = ttls?.ToArray() ?? Array.Empty<int>();
            var allGood = true;
            foreach (var ttl in list) {
                if (dnssecSigned && ttl >= min && ttl < 3600) {
                    var msg = $"{recordType} TTL {ttl} is shorter than recommended 3600 seconds for DNSSEC-signed zones.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooShortForDnssec, msg);
                    allGood = false;
                }
                if (ttl < min) {
                    var msg = $"{recordType} TTL {ttl} is shorter than recommended {min} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooShort, msg);
                    allGood = false;
                } else if (ttl > max) {
                    var msg = $"{recordType} TTL {ttl} exceeds recommended {max} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.TooLong, msg);
                    allGood = false;
                }
            }

            if (list.Any() && allGood) {
                logger?.WriteInformationCode(TtlCodes.Optimal, $"{recordType} TTLs within recommended range.");
            }

            if ((recordType == "A" || recordType == "AAAA") && ATtls.Any() && AaaaTtls.Any()) {
                var avgA = ATtls.Average();
                var avgAaaa = AaaaTtls.Average();
                var ratio = Math.Max(avgA, avgAaaa) / Math.Min(avgA, avgAaaa);
                if (ratio >= 2 && !_warnings.Any(w => w.StartsWith("A and AAAA TTLs differ", StringComparison.Ordinal))) {
                    var msg = $"A and AAAA TTLs differ significantly: A {avgA} vs AAAA {avgAaaa} seconds.";
                    _warnings.Add(msg);
                    logger?.WriteWarningCode(TtlCodes.A_AAAA_Mismatch, msg);
                } else if (ratio < 2) {
                    logger?.WriteInformationCode(TtlCodes.A_AAAA_Aligned, "A and AAAA TTLs are aligned.");
                }
            }
        }
    }
}
