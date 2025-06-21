using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {
    public class DkimAnalysis {
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();

        public async Task AnalyzeDkimRecords(string selector, IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            await Task.Yield(); // To avoid warning about lack of 'await'

            var dkimRecordList = dnsResults.ToList();
            var analysis = new DkimRecordAnalysis {
                DkimRecordExists = dkimRecordList.Any(),
            };
            // Initialize DkimRecord explicitly, though property initializer already does this.
            // This ensures clarity if the property initializer is ever removed.
            analysis.DkimRecord = string.Empty;

            // create a single string from the list of DnsResult objects
            foreach (var record in dkimRecordList) {
                analysis.Name = record.Name;
                if (record.Data != null && record.Data.Any()) {
                    foreach (var dataPart in record.Data) {
                        analysis.DkimRecord += dataPart;
                    }
                } else if (!string.IsNullOrEmpty(record.DataRaw)) {
                    analysis.DkimRecord = record.DataRaw; // Use assignment as per current subtask
                }
            }

            logger.WriteVerbose($"Analyzing DKIM record {analysis.DkimRecord}");

            if (analysis.DkimRecord == null) {
                return;
            }

            // check the DKIM record starts correctly
            analysis.StartsCorrectly = analysis.DkimRecord.StartsWith("v=DKIM1", System.StringComparison.OrdinalIgnoreCase);

            // loop through the tags of the DKIM record
            var tags = analysis.DkimRecord.Split(';');
            foreach (var tag in tags) {
                var keyValue = tag.Split(new[] { '=' }, 2);
                if (keyValue.Length == 2) {
                    var key = keyValue[0].Trim();
                    var value = keyValue[1].Trim();
                    switch (key) {
                        case "p":
                            analysis.PublicKey = value;
                            break;
                        case "s":
                            analysis.ServiceType = value;
                            break;
                        case "t":
                            analysis.Flags = value;
                            break;
                        case "k":
                            analysis.KeyType = value;
                            break;
                        case "h":
                            analysis.HashAlgorithm = value;
                            break;
                    }
                }
            }

            // check the public key exists
            analysis.PublicKeyExists = !string.IsNullOrEmpty(analysis.PublicKey);
            // check the service type exists
            analysis.KeyTypeExists = !string.IsNullOrEmpty(analysis.KeyType);

            AnalysisResults[selector] = analysis;
        }
    }

    public class DkimRecordAnalysis {
        public string Name { get; set; }
    public string DkimRecord { get; set; } = string.Empty;
        public bool DkimRecordExists { get; set; }
        public bool StartsCorrectly { get; set; }
        public bool PublicKeyExists { get; set; }
        public bool KeyTypeExists { get; set; }
        public string PublicKey { get; set; }
        public string ServiceType { get; set; }
        public string Flags { get; set; }
        public string KeyType { get; set; }
        public string HashAlgorithm { get; set; }
    }
}
