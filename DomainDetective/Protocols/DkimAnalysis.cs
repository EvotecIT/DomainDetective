using DnsClientX;
using DomainDetective.Definitions;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public class DkimAnalysis {
        public Dictionary<string, DkimRecordAnalysis> AnalysisResults { get; private set; } = new Dictionary<string, DkimRecordAnalysis>();

        public void Reset() {
            AnalysisResults = new Dictionary<string, DkimRecordAnalysis>();
        }

        public async Task AnalyzeDkimRecords(string selector, IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
            await Task.Yield(); // To avoid warning about lack of 'await'

            if (dnsResults == null) {
                logger?.WriteVerbose("DNS query returned no results.");
                return;
            }

            var dkimRecordList = dnsResults.ToList();
            var analysis = new DkimRecordAnalysis {
                DkimRecordExists = dkimRecordList.Any(),
            };

            // create a single string from the list of DnsResult objects
            foreach (var record in dkimRecordList) {
                analysis.Name = record.Name;
                if (record.DataStringsEscaped != null && record.DataStringsEscaped.Length > 0) {
                    analysis.DkimRecord += string.Join(string.Empty, record.DataStringsEscaped);
                } else {
                    analysis.DkimRecord += record.Data;
                }
            }

            logger.WriteVerbose($"Analyzing DKIM record {analysis.DkimRecord}");

            if (analysis.DkimRecord == null) {
                return;
            }

            // check the DKIM record starts correctly
            analysis.StartsCorrectly = analysis.DkimRecord.StartsWith("v=DKIM1");

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

        public async Task<string?> QueryWellKnownSelectors(string domainName, DnsConfiguration dnsConfiguration, InternalLogger logger, CancellationToken cancellationToken = default) {
            Reset();

            foreach (var selector in DKIMSelectors.GuessSelectors()) {
                var dkim = await dnsConfiguration.QueryDNS($"{selector}._domainkey.{domainName}", DnsRecordType.TXT, "DKIM1", cancellationToken);
                if (dkim.Any()) {
                    await AnalyzeDkimRecords(selector, dkim, logger);
                    return selector;
                }
            }

            return null;
        }
    }

    public class DkimRecordAnalysis {
        public string Name { get; set; }
        public string DkimRecord { get; set; }
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