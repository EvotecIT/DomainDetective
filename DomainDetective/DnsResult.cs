using System.Collections.Generic;
using System.Linq;
using DnsClient;
using DnsClient.Protocol;
using DnsClientX;

namespace DomainDetective {
    public class DnsResult {
        public string Name { get; set; }
        public string[] Data { get; set; }
        public string DataJoined { get; set; }

        public static IEnumerable<DnsResult> TranslateFromDnsQueryResponse(IDnsQueryResponse response, string type, string filter) {
            if (response == null || response.Answers == null) {
                yield break;
            }
            if (type == "TXT") {
                foreach (TxtRecord answer in response.Answers) {
                    // we join text to be able to filter properly on the whole string
                    var data = string.Join("", answer.EscapedText);
                    if (filter != null && !data.ToLowerInvariant().Contains(filter.ToLowerInvariant())) {
                        continue;
                    }
                    var dnsResult = new DnsResult {
                        Name = answer.DomainName,
                        Data = answer.EscapedText.ToArray(),
                        DataJoined = data,
                    };
                    yield return dnsResult;
                }
            }
        }

        public static IEnumerable<DnsResult> TranslateFromDohResponse(DnsResponse response, string type, string filter) {
            if (response.Answers == null) {
                yield break;
            }
            foreach (var answer in response.Answers) {
                // we join text to be able to filter properly on the whole string
                var data = answer.Data;
                if (filter != null && !data.ToLowerInvariant().Contains(filter.ToLowerInvariant())) {
                    continue;
                }
                var dnsResult = new DnsResult {
                    Name = answer.Name,
                    Data = answer.DataStringsEscaped,
                    DataJoined = data
                };
                yield return dnsResult;
            }
        }
    }
}