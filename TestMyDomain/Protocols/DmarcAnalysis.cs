using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestMyDomain.Protocols {
    /// <summary>
    ///
    ///
    /// To analyze DMARC records, you would need to follow the DMARC specification(RFC 7489). Here are some of the key points:
    /// 1.	The DMARC record must start with "v=DMARC1".
    /// 2.	The DMARC record should not have more than 255 characters.
    /// 3.	The DMARC record should have a valid "p" tag, which is the policy tag.It can have three values: "none", "quarantine", or "reject".
    /// 4.	The DMARC record can have an optional "rua" tag, which is the URI for aggregate reports.
    /// 5.	The DMARC record can have an optional "ruf" tag, which is the URI for forensic reports.
    /// 6.	The DMARC record can have an optional "pct" tag, which is the percentage of messages subjected to filtering.
    /// </summary>
    public class DmarcAnalysis {
        public string DmarcRecord { get; private set; }
        public bool DmarcRecordExists { get; private set; } // should be true
        public bool StartsCorrectly { get; private set; } // should be true
        public bool ExceedsCharacterLimit { get; private set; } // should be false
        public string Policy { get; private set; }
        public string Rua { get; private set; }
        public string Ruf { get; private set; }
        public int Pct { get; private set; }


        public string SubPolicy { get; private set; }
        public int ReportingInterval { get; private set; }
        public string FailureReportingOptions { get; private set; }
        public string DkimAlignment { get; private set; }
        public string SpfAlignment { get; private set; }

        public async Task AnalyzeDmarcRecords(IEnumerable<DnsResult> dnsResults, InternalLogger logger) {
            var dmarcRecordList = dnsResults.ToList();
            DmarcRecordExists = dmarcRecordList.Any();

            // create a single string from the list of DnsResult objects
            foreach (var record in dmarcRecordList) {
                foreach (var data in record.Data) {
                    DmarcRecord = data;
                }
            }

            logger.WriteVerbose($"Analyzing DMARC record {DmarcRecord}");

            // check the character limit
            ExceedsCharacterLimit = DmarcRecord.Length > 255;

            // check the DMARC record starts correctly
            StartsCorrectly = DmarcRecord.StartsWith("v=DMARC1");

            // loop through the tags of the DMARC record
            var tags = DmarcRecord.Split(';');
            foreach (var tag in tags) {
                var keyValue = tag.Split('=');
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            Policy = value;
                            break;
                        case "sp":
                            SubPolicy = value;
                            break;
                        case "ri":
                            ReportingInterval = int.Parse(value);
                            break;
                        case "fo":
                            FailureReportingOptions = value;
                            break;
                        case "adkim":
                            DkimAlignment = value;
                            break;
                        case "aspf":
                            SpfAlignment = value;
                            break;
                        case "rua":
                            Rua = value;
                            break;
                        case "ruf":
                            Ruf = value;
                            break;
                    }
                }
            }
        }
    }
}
