using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs analysis of NS records for a domain.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class NSAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        public Func<string, DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }
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

        /// <summary>
        /// Executes a DNS query for the specified record type.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        private async Task<IEnumerable<DnsResponse>> QueryFullDns(string name, DnsRecordType type) {
            if (QueryDnsFullOverride != null) {
                return await QueryDnsFullOverride(name, type);
            }

            return await DnsConfiguration.QueryFullDNS(new[] { name }, type);
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
            NsRecords = new List<string>();
            NsRecordExists = false;
            HasDuplicates = false;
            AtLeastTwoRecords = false;
            AllHaveAOrAaaa = true;
            PointsToCname = false;
            HasDiverseLocations = false;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var nsList = dnsResults.ToList();
            NsRecordExists = nsList.Any();
            AtLeastTwoRecords = nsList.Count >= 2;

            foreach (var record in nsList) {
                var host = record.Data.Trim('.');
                NsRecords.Add(host);
            }

            HasDuplicates = NsRecords.Count != NsRecords.Distinct(StringComparer.OrdinalIgnoreCase).Count();

            HashSet<string> subnets = new(StringComparer.OrdinalIgnoreCase);

            foreach (var ns in NsRecords) {
                var cname = await QueryDns(ns, DnsRecordType.CNAME);
                PointsToCname = PointsToCname || (cname != null && cname.Any());

                var a = await QueryDns(ns, DnsRecordType.A);
                var aaaa = await QueryDns(ns, DnsRecordType.AAAA);
                if ((a == null || !a.Any()) && (aaaa == null || !aaaa.Any())) {
                    AllHaveAOrAaaa = false;
                }

                foreach (var answer in a ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                    }
                }

                foreach (var answer in aaaa ?? Array.Empty<DnsAnswer>()) {
                    if (IPAddress.TryParse(answer.Data, out var ip)) {
                        subnets.Add(ip.GetSubnetKey());
                    }
                }
            }

            HasDiverseLocations = subnets.Count >= 2;
        }

        /// <summary>
        /// Analyzes delegation information from the parent zone.
        /// </summary>
        /// <param name="domainName">Domain being checked.</param>
        public async Task AnalyzeParentDelegation(string domainName, InternalLogger logger) {
            ParentNsRecords = new List<string>();
            DelegationMatches = false;
            GlueRecordsComplete = true;
            GlueRecordsConsistent = true;

            var parent = GetParentZone(domainName);
            if (string.IsNullOrEmpty(parent)) {
                logger?.WriteVerbose("No parent zone for {0}", domainName);
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
            if (RecursionTestOverride != null) {
                return await RecursionTestOverride(server);
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
                logger?.WriteVerbose("Recursion test failed for {0}: {1}", server, ex.Message);
                return false;
            }
        }
    }
}