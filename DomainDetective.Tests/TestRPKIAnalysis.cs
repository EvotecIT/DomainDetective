using DnsClientX;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestRPKIAnalysis {
        [Fact]
        public async Task ValidatesRpki() {
            var analysis = new RPKIAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (n, t) => t == DnsRecordType.A
                    ? Task.FromResult(new[] { new DnsAnswer { DataRaw = "1.1.1.1" } })
                    : Task.FromResult(Array.Empty<DnsAnswer>()),
                QueryRpkiOverride = _ => Task.FromResult(("1.1.1.0/24", 64512, true))
            };
            await analysis.Analyze("example.com", new InternalLogger());
            var result = Assert.Single(analysis.Results);
            Assert.Equal("1.1.1.1", result.IpAddress);
            Assert.Equal("1.1.1.0/24", result.Prefix);
            Assert.Equal(64512, result.Asn);
            Assert.True(result.Valid);
        }
    }
}
