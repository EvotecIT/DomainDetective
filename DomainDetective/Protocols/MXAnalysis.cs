using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    ///
    ///
    /// Here are some of the key points for MX record analysis:
    /// 1.	The MX record should exist for the domain.
    /// 2.	The MX record should not point to a CNAME.
    /// 3.	The MX record should not point to an IP address.
    /// 4.	The MX record should not point to a domain that doesn't exist.
    /// 5.	The MX record should not point to a domain that doesn't have an A or AAAA record.
    /// </summary>
    public class MXAnalysis {
        public DnsConfiguration DnsConfiguration { get; set; }
        public Func<string, DnsRecordType, Task<DnsAnswer[]>>? QueryDnsOverride { private get; set; }
        public List<string> MxRecords { get; private set; } = new List<string>();
        public bool MxRecordExists { get; private set; } // should be true
        public bool PointsToCname { get; private set; } // should be false
        public bool PointsToIpAddress { get; private set; } // should be false
        public bool PointsToNonExistentDomain { get; private set; } // should be false
        public bool PointsToDomainWithoutAOrAaaaRecord { get; private set; } // should be false
        public bool PrioritiesInOrder { get; private set; } // RFC 5321 section 5.1
        public bool HasBackupServers { get; private set; }

        private async Task<DnsAnswer[]> QueryDns(string name, DnsRecordType type) {
            if (QueryDnsOverride != null) {
                return await QueryDnsOverride(name, type);
            }

            return await DnsConfiguration.QueryDNS(name, type);
        }

        public async Task AnalyzeMxRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            // reset properties for repeated calls
            MxRecords = new List<string>();
            MxRecordExists = false;
            PointsToCname = false;
            PointsToIpAddress = false;
            PointsToNonExistentDomain = false;
            PointsToDomainWithoutAOrAaaaRecord = false;
            PrioritiesInOrder = true;
            HasBackupServers = false;

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var mxRecordList = dnsResults.ToList();
            MxRecordExists = mxRecordList.Any();

            var parsed = new List<(int Preference, string Host)>();
            foreach (var record in mxRecordList) {
                MxRecords.Add(record.Data);
                var parts = record.Data.Split(new[] { ' ' }, 2, System.StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 2 && int.TryParse(parts[0], out var pref)) {
                    parsed.Add((pref, parts[1].Trim('.')));
                }
            }

            logger.WriteVerbose($"Analyzing MX records {string.Join(", ", MxRecords)}");

            var preferences = parsed.Select(p => p.Preference).ToList();
            if (preferences.Count > 1) {
                var sorted = preferences.OrderBy(p => p).ToList();
                PrioritiesInOrder = preferences.SequenceEqual(sorted);
                HasBackupServers = preferences.Distinct().Count() > 1;
            }

            foreach (var (_, host) in parsed) {
                var cnameResults = await QueryDns(host, DnsRecordType.CNAME);
                PointsToCname = PointsToCname || (cnameResults != null && cnameResults.Any());

                PointsToIpAddress = PointsToIpAddress || IPAddress.TryParse(host, out _);

                var aResults = await QueryDns(host, DnsRecordType.A);
                var aaaaResults = await QueryDns(host, DnsRecordType.AAAA);
                var noA = aResults == null || !aResults.Any();
                var noAAAA = aaaaResults == null || !aaaaResults.Any();
                PointsToNonExistentDomain = PointsToNonExistentDomain || (noA && noAAAA);
                PointsToDomainWithoutAOrAaaaRecord = PointsToDomainWithoutAOrAaaaRecord || (noA && noAAAA);
            }
        }

        /// <summary>
        /// Validates MX record configuration based on collected analysis.
        /// </summary>
        /// <returns>
        /// <c>true</c> if configuration meets basic requirements; otherwise, <c>false</c>.
        /// </returns>
        public bool ValidMxConfiguration =>
            MxRecordExists
            && !PointsToCname
            && !PointsToIpAddress
            && !PointsToNonExistentDomain
            && !PointsToDomainWithoutAOrAaaaRecord;

        public bool ValidateMxConfiguration() => ValidMxConfiguration;
    }

}