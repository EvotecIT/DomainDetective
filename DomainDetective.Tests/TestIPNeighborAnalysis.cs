using DnsClientX;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestIPNeighborAnalysis {
        [Fact]
        public async Task CollectsNeighbors() {
            var analysis = new IPNeighborAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => {
                    if (type == DnsRecordType.A) return Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } });
                    if (type == DnsRecordType.PTR) return Task.FromResult(new[] { new DnsAnswer { DataRaw = "ptr.example.com." } });
                    return Task.FromResult(System.Array.Empty<DnsAnswer>());
                },
                PassiveDnsLookupOverride = ip => Task.FromResult(new List<string> { "foo.com" })
            };
            await analysis.Analyze("example.com", new InternalLogger());
            Assert.Contains(analysis.Results, r => r.IpAddress == "1.1.1.1" && r.Domains.Contains("foo.com"));
        }
    }
}
