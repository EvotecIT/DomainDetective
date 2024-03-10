using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Protocols;

public class CAAAnalysis {
    public List<CAARecordAnalysis> AnalysisResults { get; private set; } = new List<CAARecordAnalysis>();

    public async Task AnalyzeCAARecords(IEnumerable<DnsResult> dnsResults, InternalLogger logger) {
        var caaRecordList = dnsResults.ToList();

        // create a single string from the list of DnsResult objects
        foreach (var record in caaRecordList) {
            var analysis = new CAARecordAnalysis();

            foreach (var data in record.Data) {
                var caaRecord = data;

                logger.WriteVerbose($"Analyzing CAA record {caaRecord}");

                // loop through the properties of the CAA record
                var properties = caaRecord.Split(' ');
                if (properties.Length == 3) {
                    var key = properties[1].Trim();
                    var value = properties[2].Trim().Trim('"'); // remove quotes from value
                    switch (key) {
                        case "issue":
                            analysis.Issue.Add(value);
                            break;
                        case "issuewild":
                            analysis.Issuewild.Add(value);
                            break;
                        case "iodef":
                            analysis.Iodef.Add(value);
                            break;
                    }
                }
            }

            AnalysisResults.Add(analysis);
        }
    }
}

public class CAARecordAnalysis {
    public List<string> Issue { get; set; } = new List<string>();
    public List<string> Issuewild { get; set; } = new List<string>();
    public List<string> Iodef { get; set; } = new List<string>();
}