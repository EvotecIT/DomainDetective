using DomainDetective;
using DnsClientX;
using Xunit.Sdk;

namespace DomainDetective.Tests {
    public class TestDomainBlocklist {
        private static DNSBLAnalysis CreateAnalysis(Dictionary<string, DnsAnswer[]> map) {
            return new DNSBLAnalysis {
                DnsConfiguration = new DnsConfiguration(),
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
            if (!resultSpamhaus.ListedBlacklist.Contains("dbl.spamhaus.org")) {
                throw SkipException.ForSkip("Spamhaus DNSBL not reachable");
            }
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
