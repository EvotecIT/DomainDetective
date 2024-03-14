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
        public List<string> MxRecords { get; private set; } = new List<string>();
        public bool MxRecordExists { get; private set; } // should be true
        public bool PointsToCname { get; private set; } // should be false
        public bool PointsToIpAddress { get; private set; } // should be false
        public bool PointsToNonExistentDomain { get; private set; } // should be false
        public bool PointsToDomainWithoutAOrAaaaRecord { get; private set; } // should be false

        public async Task AnalyzeMxRecords(IEnumerable<DnsResult> dnsResults, InternalLogger logger) {
            var mxRecordList = dnsResults.ToList();
            MxRecordExists = mxRecordList.Any();

            // create a list of strings from the list of DnsResult objects
            foreach (var record in mxRecordList) {
                foreach (var data in record.Data) {
                    MxRecords.Add(data);
                }
            }

            logger.WriteVerbose($"Analyzing MX records {string.Join(", ", MxRecords)}");

            // loop through the MX records for remaining checks
            foreach (var mxRecord in MxRecords) {
                // check if the MX record points to a CNAME
                var cnameResults = await DomainHealthCheck.QueryDNS(mxRecord, "CNAME", DnsProvider.DnsOverHttps, "");
                PointsToCname = cnameResults != null && cnameResults.Any();

                // check if the MX record points to an IP address
                PointsToIpAddress = IPAddress.TryParse(mxRecord, out _);

                // check if the MX record points to a non-existent domain
                var aResults = await DomainHealthCheck.QueryDNS(mxRecord, "A", DnsProvider.DnsOverHttps, "");
                var aaaaResults = await DomainHealthCheck.QueryDNS(mxRecord, "AAAA", DnsProvider.DnsOverHttps, "");
                PointsToNonExistentDomain = (aResults == null || !aResults.Any()) && (aaaaResults == null || !aaaaResults.Any());

                // check if the MX record points to a domain without an A or AAAA record
                PointsToDomainWithoutAOrAaaaRecord = (aResults == null || !aResults.Any()) && (aaaaResults == null || !aaaaResults.Any());
            }
        }
    }

}
