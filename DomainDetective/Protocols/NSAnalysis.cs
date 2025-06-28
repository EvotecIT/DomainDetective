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
    public class NSAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
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

        /// <summary>
        /// Executes a DNS query for the specified record type.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
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

            var parentNs = await QueryDns(domainName, DnsRecordType.NS);
            foreach (var rec in parentNs) {
                ParentNsRecords.Add(rec.Data.Trim('.'));
            }

            DelegationMatches = new HashSet<string>(ParentNsRecords, StringComparer.OrdinalIgnoreCase)
                .SetEquals(NsRecords);

            foreach (var ns in ParentNsRecords) {
                if (ns.EndsWith('.' + domainName, StringComparison.OrdinalIgnoreCase)) {
                    var parentA = await QueryDns(ns, DnsRecordType.A);
                    var parentAaaa = await QueryDns(ns, DnsRecordType.AAAA);
                    if ((parentA == null || !parentA.Any()) && (parentAaaa == null || !parentAaaa.Any())) {
                        GlueRecordsComplete = false;
                        continue;
                    }

                    var childA = await QueryDns(ns, DnsRecordType.A);
                    var childAaaa = await QueryDns(ns, DnsRecordType.AAAA);
                    if (!AnswersMatch(parentA, childA) || !AnswersMatch(parentAaaa, childAaaa)) {
                        GlueRecordsConsistent = false;
                    }
                }
            }
        }
    }
}