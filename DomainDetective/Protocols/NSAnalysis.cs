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

        /// <summary>
        /// Executes a DNS query for the specified record type.
        /// </summary>
        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
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
    }
}