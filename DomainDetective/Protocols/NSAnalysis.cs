using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using System.Text.Json;

namespace DomainDetective {
    /// <summary>
    /// Performs analysis of NS records for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class NSAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        /// <summary>Configuration used for DNS queries.</summary>
        public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

        /// <summary>Allows injection of a DNS query implementation for testing.</summary>
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }

        /// <summary>Optional full DNS query override that returns raw responses.</summary>
        public Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }

        /// <summary>Optional override for recursion testing logic.</summary>
        public Func<string, Task<bool>>? RecursionTestOverride { private get; set; }
        public List<string> NsRecords { get; private set; } = new();
        public bool NsRecordExists { get; private set; }
        public bool HasDuplicates { get; private set; }
        public bool AtLeastTwoRecords { get; private set; }
        public bool AllHaveAOrAaaa { get; private set; }
        public bool PointsToCname { get; private set; }
        public bool HasDiverseLocations { get; private set; }
        public List<string> ParentNsRecords { get; private set; } = new();
        public bool DelegationMatches { get; private set; }
        public bool GlueRecordsComplete { get; private set; }
        public bool GlueRecordsConsistent { get; private set; }

        public Dictionary<string, bool> RootServerResponses { get; private set; } = new();
        public Dictionary<string, bool> RecursionEnabled { get; private set; } = new();

        // ASN diversity (provider diversity)
        public Dictionary<string, int> AsnByIp { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
        public int AsnDistinctCount { get; private set; }

        /// <summary>Override for ASN lookup in tests.</summary>
        public Func<string, Task<int?>>? LookupAsnOverride { private get; set; }

        public List<Assessment> Assessments { get; } = new();

        /// <summary>
        /// Executes a DNS query for the specified record type.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            var queryDnsOverride = QueryDnsOverride;
            if (queryDnsOverride != null) {
                // Try exact first
                var res = await queryDnsOverride(name, type);
                if (res != null && res.Length > 0) return res;
                // Fallback to toggling trailing dot to accommodate tests and mixed data
                string alt = name.EndsWith(".", StringComparison.Ordinal) ? name.TrimEnd('.') : name + ".";
                try { res = await queryDnsOverride(alt, type); } catch { res = Array.Empty<DnsAnswer>(); }
                return res ?? Array.Empty<DnsAnswer>();
            }

            return await DnsConfiguration.QueryDNS(name, type) ?? Array.Empty<DnsAnswer>();
        }

        private async Task<IEnumerable<DnsResponse>> QueryFullDns(string name, DnsRecordType type) {
            var queryDnsFullOverride = QueryDnsFullOverride;
            if (queryDnsFullOverride != null) {
                return await queryDnsFullOverride(name, type);
            }

            return await DnsConfiguration.QueryFullDNS(new[] { name }, type) ?? Array.Empty<DnsResponse>();
        }

        private static string? GetParentZone(string domain) {
            if (string.IsNullOrWhiteSpace(domain) || !domain.Contains('.')) {
                return null;
            }
            var parts = domain.Trim('.').Split('.');
            return parts.Length > 1 ? string.Join(".", parts.Skip(1)) : null;
        }

        private static bool AnswersMatch(IEnumerable<DnsAnswer>? first, IEnumerable<DnsAnswer>? second) {
            var a = new HashSet<string>(first?.Select(f => f.Data) ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var b = new HashSet<string>(second?.Select(s => s.Data) ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            return a.SetEquals(b);
        }

        /// <summary>
        /// Queries the parent zone for NS records and glue information.
        /// </summary>
        public async Task<(List<string> NsRecords, Dictionary<string, List<string>> GlueRecords)> QueryParentNsGlue(string domainName, InternalLogger logger) {
            List<string> nsRecords = new();
            Dictionary<string, List<string>> glueRecords = new(StringComparer.OrdinalIgnoreCase);

            var responses = (await QueryFullDns(domainName, DnsRecordType.NS)).ToArray();
            if (responses.Length == 0) {
                return (nsRecords, glueRecords);
            }

            var response = responses[0];
            foreach (var rec in response.Answers ?? Array.Empty<DnsAnswer>()) {
                nsRecords.Add(rec.Data.Trim('.'));
            }

            foreach (var add in response.Additional ?? Array.Empty<DnsAnswer>()) {
                if (add.Type == DnsRecordType.A || add.Type == DnsRecordType.AAAA) {
                    var host = add.Name.Trim('.');
                    if (!glueRecords.TryGetValue(host, out var list)) {
                        list = new List<string>();
                        glueRecords[host] = list;
                    }
                    list.Add(add.Data);
                }
            }

            return (nsRecords, glueRecords);
        }

        /// <summary>
        /// Processes NS records and determines their properties.
        /// </summary>
        public async Task AnalyzeNsRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "NS");
            NsRecords = new List<string>();
            NsRecordExists = false;
            HasDuplicates = false;
            AtLeastTwoRecords = false;
            AllHaveAOrAaaa = true;
            PointsToCname = false;
            HasDiverseLocations = false;

            if (dnsResults == null) {
                logger.WriteVerbose("DNS query returned no results.");
                return;
            }

            var nsList = dnsResults.ToList();
            NsRecordExists = nsList.Any();
            AtLeastTwoRecords = nsList.Count >= 2;

            var missingAddressHosts = new List<string>();
            foreach (var record in nsList) {
                var host = record.Data.Trim('.');
                NsRecords.Add(host);
            }

            HasDuplicates = NsRecords.Count != NsRecords.Distinct(StringComparer.OrdinalIgnoreCase).Count();

            HashSet<string> subnets = new(StringComparer.OrdinalIgnoreCase);

            var allIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var ns in NsRecords) {
                var cname = await QueryDns(ns, DnsRecordType.CNAME);
                PointsToCname = PointsToCname || (cname != null && cname.Any());

                var a = await QueryDns(ns, DnsRecordType.A);
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA);
                if ((a == null || !a.Any()) && (aaaa == null || !aaaa.Any())) {
                    AllHaveAOrAaaa = false;
                    missingAddressHosts.Add(ns);
                }

                foreach (var answer in a ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                        allIps.Add(ip.ToString());
                    }
                }

                foreach (var answer in aaaa ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                        allIps.Add(ip.ToString());
                    }
                }
            }

            // ASN lookups (best-effort)
            AsnByIp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var ip in allIps)
            {
                try {
                    int? asn = LookupAsnOverride != null
                        ? await LookupAsnOverride(ip)
                        : await LookupAsnAsync(ip, CancellationToken.None);
                    if (asn.HasValue) AsnByIp[ip] = asn.Value;
                } catch { /* ignore lookup failures */ }
            }
            AsnDistinctCount = AsnByIp.Values.Distinct().Count();

            HasDiverseLocations = subnets.Count >= 2 || AsnDistinctCount >= 2;

            // Emit assessments for common NS issues
            if (!NsRecordExists) {
                logger.WriteWarningCode(NSCodes.Missing, "No NS records found");
            }
            if (HasDuplicates) {
                logger.WriteWarningCode(NSCodes.Duplicate, "Duplicate NS records detected");
            }
            if (!AtLeastTwoRecords) {
                logger.WriteWarningCode(NSCodes.TooFewRecords, "Fewer than two NS records published");
            }
            if (PointsToCname) {
                logger.WriteWarningCode(NSCodes.CnameTarget, "One or more NS hostnames point to CNAMEs");
            }
            if (!AllHaveAOrAaaa) {
                foreach (var host in missingAddressHosts) {
                    using (_collector.PushTarget(host))
                        logger.WriteWarningCode(NSCodes.MissingAddressRecords, "NS hostname has no A/AAAA address records");
                }
            }
            if (!HasDiverseLocations) {
                logger.WriteWarningCode(NSCodes.LowDiversity, "NS hosts lack diversity across networks");
            } else {
                // Surface a clear positive that highlights ASN/vendor diversity explicitly
                logger.WriteInformationCode(NSCodes.HighDiversity, $"Authoritative NS are diverse across networks/providers (ASNs: {AsnDistinctCount})");
            }
        }

        private static async Task<int?> LookupAsnAsync(string ip, CancellationToken ct)
        {
            try {
                using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, $"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}");
                using var response = await SharedHttpClient.Instance.SendAsync(req, ct).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
#if NET5_0_OR_GREATER
                var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
#else
                var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                using var doc = await JsonDocument.ParseAsync(stream).ConfigureAwait(false);
#endif
                if (!doc.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("asns", out var asns)) return null;
                if (asns.ValueKind != JsonValueKind.Array || asns.GetArrayLength() == 0) return null;
                var first = asns[0];
                if (first.TryGetProperty("asn", out var asnProp)) return asnProp.GetInt32();
                return null;
            } catch { return null; }
        }

        /// <summary>
        /// Analyzes delegation information from the parent zone.
        /// </summary>
        /// <param name="domainName">Domain being checked.</param>
        /// <param name="logger">Logger used for diagnostics.</param>
        public async Task AnalyzeParentDelegation(string domainName, InternalLogger logger) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "NS", target: domainName);
            ParentNsRecords = new List<string>();
            DelegationMatches = false;
            GlueRecordsComplete = true;
            GlueRecordsConsistent = true;

            var parent = GetParentZone(domainName);
            if (string.IsNullOrEmpty(parent)) {
                logger.WriteVerbose("No parent zone for {0}", domainName);
                return;
            }

            var (parentNs, glue) = await QueryParentNsGlue(domainName, logger);
            ParentNsRecords = parentNs;

            if (!ParentNsRecords.Any()) {
                GlueRecordsComplete = false;
                return;
            }

            DelegationMatches = new HashSet<string>(ParentNsRecords, StringComparer.OrdinalIgnoreCase)
                .SetEquals(NsRecords);

            foreach (var ns in ParentNsRecords) {
                if (!ns.EndsWith('.' + domainName, StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                glue.TryGetValue(ns, out var parentGlue);
                if (parentGlue == null || parentGlue.Count == 0) {
                    GlueRecordsComplete = false;
                    continue;
                }

                var childA = await QueryDns(ns, DnsRecordType.A);
                var childAaaa = await QueryDns(ns, DnsRecordType.AAAA);
                var combined = childA.Concat(childAaaa ?? Array.Empty<DnsAnswer>()).Select(a => a.Data);
                if (!new HashSet<string>(parentGlue, StringComparer.OrdinalIgnoreCase).SetEquals(combined)) {
                    GlueRecordsConsistent = false;
                }
            }

            if (!DelegationMatches) {
                logger.WriteWarningCode(NSCodes.DelegationMismatch, "Parent delegation NS set differs from child zone NS set");
            }
            if (!GlueRecordsComplete) {
                logger.WriteWarningCode(NSCodes.GlueIncomplete, "Parent zone missing glue records for in-bailiwick NS");
            }
            if (!GlueRecordsConsistent) {
                logger.WriteWarningCode(NSCodes.GlueInconsistent, "Parent glue records do not match child A/AAAA records");
            }
        }

        public async Task QueryRootServers(InternalLogger logger) {
            RootServerResponses = new Dictionary<string, bool>();
            var roots = await QueryDns(".", DnsRecordType.NS);
            foreach (var root in roots) {
                var host = root.Data.Trim('.');
                bool responsive = false;
                try {
                    var a = await QueryDns(host, DnsRecordType.A);
                    if (a != null && a.Any()) {
                        responsive = true;
                    } else {
                        var aaaa = await QueryDns(host, DnsRecordType.AAAA);
                        responsive = aaaa != null && aaaa.Any();
                    }
                } catch {
                    responsive = false;
                }
                RootServerResponses[host] = responsive;
            }
        }

        public async Task TestRecursion(InternalLogger logger) {
            RecursionEnabled = new Dictionary<string, bool>();
            foreach (var ns in NsRecords) {
                var host = ns.Trim('.');
                bool recursion = await CheckRecursionAsync(host, logger);
                RecursionEnabled[host] = recursion;
                if (recursion) {
                    using var _s = AssessmentCollector.ForAnalysis(logger, this, category: "NS", target: host);
                    logger.WriteWarningCode(NSCodes.RecursionOnAuthoritative, "Authoritative NS allows recursion");
                }
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

        private static byte[] BuildQuery(string domain, ushort id) {
            var header = new byte[12];
            header[0] = (byte)(id >> 8);
            header[1] = (byte)(id & 0xFF);
            header[2] = 0x01;
            header[5] = 0x01;
            var qname = EncodeDomainName(domain, true);
            var query = new byte[header.Length + qname.Length + 4];
            Buffer.BlockCopy(header, 0, query, 0, header.Length);
            Buffer.BlockCopy(qname, 0, query, header.Length, qname.Length);
            var offset = header.Length + qname.Length;
            query[offset] = 0x00;
            query[offset + 1] = 0x01;
            query[offset + 2] = 0x00;
            query[offset + 3] = 0x01;
            return query;
        }

        private async Task<bool> CheckRecursionAsync(string server, InternalLogger logger) {
            var recursionTestOverride = RecursionTestOverride;
            if (recursionTestOverride != null) {
                return await recursionTestOverride(server);
            }
            try {
                using var udp = new System.Net.Sockets.UdpClient();
                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(5));
                var id = (ushort)new Random().Next(ushort.MaxValue);
                var query = BuildQuery("example.com", id);
#if NET8_0_OR_GREATER
                await udp.SendAsync(query, server, 53, cts.Token);
                var result = await udp.ReceiveAsync(cts.Token);
#else
                await udp.SendAsync(query, query.Length, server, 53).WaitWithCancellation(cts.Token);
                var result = await udp.ReceiveAsync().WaitWithCancellation(cts.Token);
#endif
                var data = result.Buffer;
                return data.Length > 3 && (data[3] & 0x80) != 0;
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger.WriteVerbose("Recursion test failed for {0}: {1}", server, ex.Message);
                return false;
            }
        }
    }
}
