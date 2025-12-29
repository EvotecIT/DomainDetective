using DomainDetective;
using DnsClientX;
using System.IO;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDomainBlocklist {
        private static DNSBLAnalysis CreateAnalysis(Dictionary<string, DnsAnswer[]> map) {
            var analysis = new DNSBLAnalysis(new DnsConfiguration()) {
                QueryDnsFullOverride = (names, _) => {
                    var list = new List<DnsResponse>();
                    foreach (var n in names) {
                        list.Add(new DnsResponse {
                            Answers = map.TryGetValue(n, out var a) ? a : Array.Empty<DnsAnswer>()
                        });
                    }
                    return Task.FromResult<IEnumerable<DnsResponse>>(list);
                }
            };
            EnsureDomainBlockLists(analysis);
            return analysis;
        }

        private static void EnsureDomainBlockLists(DNSBLAnalysis analysis) {
            var json = "{\"domainBlockLists\":[{\"domain\":\"multi.uribl.com\",\"enabled\":true},{\"domain\":\"dbl.spamhaus.org\",\"enabled\":true}]}";
            var tempFile = Path.GetTempFileName();
            try {
                File.WriteAllText(tempFile, json);
                analysis.LoadDnsblConfig(tempFile);
            } finally {
                File.Delete(tempFile);
            }
        }

        [Fact]
        public async Task ListedDomainsReturnPositive() {
            var map = new Dictionary<string, DnsAnswer[]>(StringComparer.OrdinalIgnoreCase) {
                ["dbltest.com.dbl.spamhaus.org"] = new[] {
                    new DnsAnswer {
                        Name = "dbltest.com.dbl.spamhaus.org",
                        DataRaw = "127.0.0.2",
                        Type = DnsRecordType.A
                    }
                },
                ["test.uribl.com.multi.uribl.com"] = new[] {
                    new DnsAnswer {
                        Name = "test.uribl.com.multi.uribl.com",
                        DataRaw = "127.0.0.2",
                        Type = DnsRecordType.A
                    }
                }
            };
            var analysis = CreateAnalysis(map);
            analysis.ClearDNSBL();
            analysis.AddDNSBL("multi.uribl.com");
            analysis.AddDNSBL("dbl.spamhaus.org");

            await analysis.IsDomainListedAsync("dbltest.com", new InternalLogger());
            var resultSpamhaus = analysis.Results["dbltest.com"];
            Assert.Contains("dbl.spamhaus.org", resultSpamhaus.ListedBlacklist);
            Assert.True(resultSpamhaus.IsBlacklisted);

            await analysis.IsDomainListedAsync("test.uribl.com", new InternalLogger());
            var resultUribl = analysis.Results["test.uribl.com"];
            Assert.Contains("multi.uribl.com", resultUribl.ListedBlacklist);
            Assert.True(resultUribl.IsBlacklisted);
        }

        [Fact]
        public async Task UnlistedDomainReturnsNegative() {
            var analysis = CreateAnalysis(new Dictionary<string, DnsAnswer[]>());
            analysis.ClearDNSBL();
            analysis.AddDNSBL("multi.uribl.com");
            analysis.AddDNSBL("dbl.spamhaus.org");

            var listed = await analysis.IsDomainListedAsync("example.com", new InternalLogger());
            Assert.False(listed);
        }
    }
}
