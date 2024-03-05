using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TestMyDomain.Protocols {
    public class DkimAnalysis {
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();

        public string DkimRecord { get; private set; }
        public bool DkimRecordExists { get; private set; } // should be true
        public bool StartsCorrectly { get; private set; } // should be true
        public bool PublicKeyExists { get; private set; } // should be true
        public bool KeyTypeExists { get; private set; } // should be true

        // short versions of the tags
        public string PublicKey { get; private set; }
        public string ServiceType { get; private set; }
        public string Flags { get; private set; }
        public string KeyType { get; private set; }
        public string HashAlgorithm { get; private set; }

        public async Task AnalyzeDkimRecords(IEnumerable<DnsResult> dnsResults, InternalLogger logger) {
            var dkimRecordList = dnsResults.ToList();
            DkimRecordExists = dkimRecordList.Any();

            // create a single string from the list of DnsResult objects
            foreach (var record in dkimRecordList) {
                foreach (var data in record.Data) {
                    DkimRecord = data;
                }
            }

            logger.WriteVerbose($"Analyzing DKIM record {DkimRecord}");

            if (DkimRecord == null) {
                return;
            }

            // check the DKIM record starts correctly
            StartsCorrectly = DkimRecord.StartsWith("v=DKIM1");

            // loop through the tags of the DKIM record
            var tags = DkimRecord.Split(';');
            foreach (var tag in tags) {
                var keyValue = tag.Split('=');
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            PublicKey = value;
                            break;
                        case "s":
                            ServiceType = value;
                            break;
                        case "t":
                            Flags = value;
                            break;
                        case "k":
                            KeyType = value;
                            break;
                        case "h":
                            HashAlgorithm = value;
                            break;
                    }
                }
            }

            // check the public key exists
            PublicKeyExists = !string.IsNullOrEmpty(PublicKey);
            // check the service type exists
            KeyTypeExists = !string.IsNullOrEmpty(KeyType);
        }
    }

    public class DkimRecordAnalysis {
        public string DkimRecord { get; set; }
        public bool DkimRecordExists { get; set; }
        public bool StartsCorrectly { get; set; }
        // ... other properties ...
    }

}
