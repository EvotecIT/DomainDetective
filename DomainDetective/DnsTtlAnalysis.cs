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
        /// <summary>Gets TTL values for AAAA records including zero values.</summary>
        public IReadOnlyList<int> AaaaTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for MX records including zero values.</summary>
        public IReadOnlyList<int> MxTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets TTL values for NS records including zero values.</summary>
        public IReadOnlyList<int> NsTtls { get; private set; } = Array.Empty<int>();
        /// <summary>Gets the TTL value for the SOA record; zero indicates no TTL or missing record.</summary>
        public int SoaTtl { get; private set; }
        /// <summary>TTL values for SPF TXT at the zone apex.</summary>
        public IReadOnlyList<int> SpfTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _dmarc TXT.</summary>
        public IReadOnlyList<int> DmarcTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _mta-sts TXT.</summary>
        public IReadOnlyList<int> MtastsTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for _smtp._tls TXT (TLS-RPT).</summary>
        public IReadOnlyList<int> TlsRptTxtTtls { get; private set; } = Array.Empty<int>();
        /// <summary>TTL values for DKIM selector TXT records, keyed by FQDN (selector._domainkey.domain).</summary>
        public Dictionary<string, IReadOnlyList<int>> DkimTxtTtls { get; private set; } = new();
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
        /// <summary>Minimum TTL for DKIM selector TXT records (seconds).</summary>
        public int MinTtlDkimSelectorSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for MTA-STS TXT records (seconds).</summary>
        public int MinTtlMtastsSeconds { get; set; } = 3600;
        /// <summary>Minimum TTL for TLS-RPT TXT records (seconds).</summary>
        public int MinTtlTlsRptSeconds { get; set; } = 3600;

        /// <summary>
        /// UDP receive timeout (milliseconds) used when querying authoritative servers directly
        /// during <see cref="AnalyzeUniformityAcrossServers"/>.
        /// </summary>
        public int UniformityQueryTimeoutMs { get; set; } = 4000;

        /// <summary>
        /// Maximum number of concurrent authoritative-server TTL queries performed by
        /// <see cref="AnalyzeUniformityAcrossServers"/>.
        /// </summary>
        public int UniformityMaxParallelism { get; set; } = 8;

	        // Per-authoritative-server TTL uniformity results
	        public Dictionary<string, int?> ServerTtlA { get; private set; } = new();
	        public Dictionary<string, int?> ServerTtlAaaa { get; private set; } = new();
	        public Dictionary<string, int?> ServerTtlNs { get; private set; } = new();
	        public Dictionary<string, int?> ServerTtlCname { get; private set; } = new();
	        public Dictionary<string, int?> ServerTtlTxtSpf { get; private set; } = new();
	        public Dictionary<string, int?> ServerTtlTxtDmarc { get; private set; } = new();
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

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            if (type == DnsRecordType.TXT) {
                return await DnsConfiguration.QueryDNS(
                    name,
                    type,
                    filter: string.Empty,
                    includeAliasesInFilter: true);
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
        private static byte[] BuildQuery(string domain, ushort qtype) {
            var header = new byte[12];
            var id = Helpers.DnsQueryIdGenerator.NextUShort();
            header[0] = (byte)(id >> 8); header[1] = (byte)(id & 0xFF);
            header[2] = 0x01; header[5] = 0x01;
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
        private static async Task<byte[]?> QueryUdp(System.Net.IPAddress server, byte[] query, System.Threading.CancellationToken token, int timeoutMs) {
            using var udp = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(server.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? System.Net.IPAddress.IPv6Any : System.Net.IPAddress.Any, 0));
            udp.Client.ReceiveTimeout = timeoutMs > 0 ? timeoutMs : 4000;
#if NET8_0_OR_GREATER
            using var cts = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(timeoutMs > 0 ? timeoutMs : 4000);
            await udp.SendAsync(query, new System.Net.IPEndPoint(server, 53));
            var res = await udp.ReceiveAsync(cts.Token);
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
                // Capture CNAME TTL - when authoritative NS returns only CNAME (for aliased records),
                // return the CNAME TTL as the authoritative value since that's what the domain owner controls.
                if (type == 5 && cnameTtl == null) cnameTtl = ttl;
                offset += rdlen;
            }
            return cnameTtl;
        }
        private async Task<int?> QueryTtlFromServer(System.Net.IPAddress ip, string name, ushort qtype, System.Threading.CancellationToken ct, int timeoutMs) {
            var q = BuildQuery(name, qtype);
            var buf = await QueryUdp(ip, q, ct, timeoutMs);
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
            AaaaTtls = Array.Empty<int>();
            MxTtls = Array.Empty<int>();
            NsTtls = Array.Empty<int>();
            SoaTtl = 0;
            SpfTxtTtls = Array.Empty<int>();
            DmarcTxtTtls = Array.Empty<int>();
            MtastsTxtTtls = Array.Empty<int>();
            TlsRptTxtTtls = Array.Empty<int>();
            DkimTxtTtls = new Dictionary<string, IReadOnlyList<int>>();

            var aRecords = await QueryDns(domainName, DnsRecordType.A);
            var aaaaRecords = await QueryDns(domainName, DnsRecordType.AAAA);
            var mxRecords = await QueryDns(domainName, DnsRecordType.MX);
            var nsRecords = await QueryDns(domainName, DnsRecordType.NS);
            var soaRecords = await QueryDns(domainName, DnsRecordType.SOA);
            var dsRecords = await QueryDns(domainName, DnsRecordType.DS);
            var txtApex = await QueryDns(domainName, DnsRecordType.TXT);
            var txtDmarc = await QueryDns($"_dmarc.{domainName}", DnsRecordType.TXT);
            var txtMtasts = await QueryDns($"_mta-sts.{domainName}", DnsRecordType.TXT);
            var txtTlsRpt = await QueryDns($"_smtp._tls.{domainName}", DnsRecordType.TXT);

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
            // Only treat TXT at _dmarc as DMARC when it actually contains a DMARC record
            DmarcTxtTtls = txtDmarc
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=DMARC1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

            MtastsTxtTtls = txtMtasts
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=STSv1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

            TlsRptTxtTtls = txtTlsRpt
                .Where(r => (r.Data ?? r.DataRaw ?? string.Empty).IndexOf("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase) >= 0)
                .Select(r => r.TTL)
                .ToArray();

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
	            ServerTtlTxtSpf = new(); ServerTtlTxtDmarc = new(); ServerTtlTxtMtasts = new(); ServerTtlTxtTlsRpt = new(); ServerTtlTxtPerName = new();
	            AUniformAcrossServers = AaaaUniformAcrossServers = NsUniformAcrossServers = CnameUniformAcrossServers = true;

	            var timeoutMs = UniformityQueryTimeoutMs > 0 ? UniformityQueryTimeoutMs : 4000;
	            var maxParallelism = UniformityMaxParallelism > 0 ? UniformityMaxParallelism : 1;
	            using var semaphore = new System.Threading.SemaphoreSlim(maxParallelism, maxParallelism);

            // Discover authoritative NS hosts and IPs via resolver
            var nsAnswers = await QueryDns(domainName, DnsRecordType.NS);
            var nsHosts = nsAnswers.Select(a => a.Data?.Trim('.') ?? string.Empty).Where(h => !string.IsNullOrEmpty(h)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var nsIps = new HashSet<System.Net.IPAddress>();
            foreach (var host in nsHosts) {
                var a = await QueryDns(host, DnsRecordType.A);
                foreach (var ans in a) {
                    if (System.Net.IPAddress.TryParse(ans.Data, out var ip)) {
                        nsIps.Add(ip);
                    }
                }
                var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                foreach (var ans in aaaa) {
                    if (System.Net.IPAddress.TryParse(ans.Data, out var ip6)) {
                        nsIps.Add(ip6);
                    }
                }
            }
            if (nsIps.Count == 0) {
                return;
            }

            async Task<int?> SafeQuery(System.Net.IPAddress server, string name, ushort qtype, string label) {
                await semaphore.WaitAsync(ct);
                try {
                    return await QueryTtlFromServer(server, name, qtype, ct, timeoutMs);
                } catch (Exception ex) {
                    logger?.WriteDebug("TTL uniformity query failed: server={0} label={1} name={2} qtype={3} error={4}", server, label, name, qtype, ex.Message);
                    return null;
                } finally {
                    semaphore.Release();
                }
            }

            var dkimSelectors = (DkimSelectors != null && DkimSelectors.Count > 0)
                ? DkimSelectors.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
                : Array.Empty<string>();

            var ipTasks = nsIps.Select(async ip => {
                ct.ThrowIfCancellationRequested();
                var key = ip.ToString();

                var aTask = SafeQuery(ip, domainName, 1, "A");
                var aaaaTask = SafeQuery(ip, domainName, 28, "AAAA");
	                var nsTask = SafeQuery(ip, domainName, 2, "NS");
	                var cnameTask = SafeQuery(ip, domainName, 5, "CNAME");
	                var txtSpfTask = SafeQuery(ip, domainName, 16, "TXT(SPF)");
	                var txtDmarcTask = SafeQuery(ip, $"_dmarc.{domainName}", 16, "TXT(DMARC)");
	                var txtMtastsTask = SafeQuery(ip, $"_mta-sts.{domainName}", 16, "TXT(MTA-STS)");
	                var txtTlsRptTask = SafeQuery(ip, $"_smtp._tls.{domainName}", 16, "TXT(TLS-RPT)");

	                await Task.WhenAll(aTask, aaaaTask, nsTask, cnameTask, txtSpfTask, txtDmarcTask, txtMtastsTask, txtTlsRptTask);

	                var dkim = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
	                if (dkimSelectors.Length > 0) {
	                    var dkimTasks = dkimSelectors
	                        .Select(async sel => {
                            var name = $"{sel}._domainkey.{domainName}";
                            var ttl = await SafeQuery(ip, name, 16, "TXT(DKIM)");
                            return (Name: name, Ttl: ttl);
                        })
	                        .ToArray();

	                    var dkimResults = await Task.WhenAll(dkimTasks);
	                    foreach (var dkimResult in dkimResults) {
	                        dkim[dkimResult.Name] = dkimResult.Ttl;
	                    }
	                }

	                return (Key: key, A: aTask.Result, Aaaa: aaaaTask.Result, Ns: nsTask.Result, Cname: cnameTask.Result, TxtSpf: txtSpfTask.Result, TxtDmarc: txtDmarcTask.Result, TxtMtasts: txtMtastsTask.Result, TxtTlsRpt: txtTlsRptTask.Result, Dkim: dkim);
	            }).ToArray();

	            var results = await Task.WhenAll(ipTasks);

	            foreach (var r in results) {
	                ServerTtlA[r.Key] = r.A;
	                ServerTtlAaaa[r.Key] = r.Aaaa;
	                ServerTtlNs[r.Key] = r.Ns;
	                ServerTtlCname[r.Key] = r.Cname;
	                ServerTtlTxtSpf[r.Key] = r.TxtSpf;
	                ServerTtlTxtDmarc[r.Key] = r.TxtDmarc;
	                ServerTtlTxtMtasts[r.Key] = r.TxtMtasts;
	                ServerTtlTxtTlsRpt[r.Key] = r.TxtTlsRpt;

	                foreach (var kv in r.Dkim) {
	                    if (!ServerTtlTxtPerName.TryGetValue(kv.Key, out var map)) {
	                        map = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
                        ServerTtlTxtPerName[kv.Key] = map;
                    }
                    map[r.Key] = kv.Value;
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

	            // TXT _mta-sts
	            var txtMtastsUniform = IsUniform(ServerTtlTxtMtasts);
	            if (!txtMtastsUniform) logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_TXT_MTASTS, "MTA-STS TXT TTL differs across authoritative name servers");
	            else logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_TXT_MTASTS, "MTA-STS TXT TTL consistent across authoritative name servers.");

	            // TXT _smtp._tls (TLS-RPT)
	            var txtTlsRptUniform = IsUniform(ServerTtlTxtTlsRpt);
	            if (!txtTlsRptUniform) logger?.WriteWarningCode(TtlCodes.NonUniformAcrossNS_TXT_TLSRPT, "TLS-RPT TXT TTL differs across authoritative name servers");
	            else logger?.WriteInformationCode(TtlCodes.UniformAcrossNS_TXT_TLSRPT, "TLS-RPT TXT TTL consistent across authoritative name servers.");

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
