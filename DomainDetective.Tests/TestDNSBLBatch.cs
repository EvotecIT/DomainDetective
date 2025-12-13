using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsblBatch {
        [Fact]
        public async Task MultipleInputsAccumulateResults() {
            var hc = new DomainHealthCheck();

            // Reduce default lists to a predictable single provider
            hc.DNSBLAnalysis.ClearDNSBL();
            hc.DNSBLAnalysis.AddDNSBL("example.test");

            // Mock DNS answers for two queries (one IP and one domain)
            var map = new Dictionary<string, DnsClientX.DnsAnswer[]>(StringComparer.OrdinalIgnoreCase) {
                ["4.3.2.1.example.test"] = new [] {
                    new DnsClientX.DnsAnswer {
                        Name = "4.3.2.1.example.test",
                        DataRaw = "127.0.0.2",
                        Type = DnsClientX.DnsRecordType.A
                    }
                },
                ["example.com.example.test"] = Array.Empty<DnsClientX.DnsAnswer>()
            };

            hc.DNSBLAnalysis.QueryDnsFullOverride = (names, _) => {
                var list = new List<DnsClientX.DnsResponse>();
                foreach (var n in names) {
                    list.Add(new DnsClientX.DnsResponse {
                        Answers = map.TryGetValue(n, out var a) ? a : Array.Empty<DnsClientX.DnsAnswer>()
                    });
                }
                return Task.FromResult<IEnumerable<DnsClientX.DnsResponse>>(list);
            };

            // Prevent network calls for MX/A during test
            hc.DNSBLAnalysis.DnsConfiguration.QueryDnsOverride = (name, type) => Task.FromResult(Array.Empty<DnsClientX.DnsAnswer>());

            await hc.CheckDNSBL(new[] { "1.2.3.4" });

            Assert.True(hc.DNSBLAnalysis.Results.ContainsKey("1.2.3.4"));

            var ipResult = hc.DNSBLAnalysis.Results["1.2.3.4"];
            Assert.True(ipResult.IsBlacklisted);
        }
    }
}
