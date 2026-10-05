using DnsClientX;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    /// <summary>
    /// TTL findings must describe the zone's configured TTLs, not how long a caching resolver has held an answer.
    /// </summary>
    public class TestDnsTtlAnalysisAuthoritative {
        private static DnsAnswer Answer(DnsRecordType type, string data, int ttl) => new() { Type = type, DataRaw = data, TTL = ttl };

        private static DnsTtlAnalysis Analysis(int resolverTtl, int? authoritativeTtl) => new() {
            DnsConfiguration = new DnsConfiguration(),
            QueryDnsOverride = (name, type) => Task.FromResult(type switch {
                DnsRecordType.A when name == "example.com" => new[] { Answer(DnsRecordType.A, "192.0.2.10", resolverTtl) },
                DnsRecordType.NS when name == "example.com" => new[] { Answer(DnsRecordType.NS, "ns1.example.net", 86400) },
                _ => System.Array.Empty<DnsAnswer>()
            }),
            AuthoritativeTtlOverride = (name, type) => Task.FromResult(type == DnsRecordType.A && name == "example.com" ? authoritativeTtl : (int?)86400)
        };

        private static string[] TooShort(DnsTtlAnalysis analysis)
            => analysis.Assessments.Where(static a => a.Code == TtlCodes.TooShort).Select(static a => a.Message).ToArray();

        [Fact]
        public async Task ResolverCountdownRaisesNoTooShortFinding() {
            DnsTtlAnalysis analysis = Analysis(resolverTtl: 71, authoritativeTtl: 300);

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.True(analysis.TtlsFromAuthoritativeServers);
            Assert.Equal(new[] { 300 }, analysis.ATtls);
            Assert.Empty(TooShort(analysis));
        }

        [Fact]
        public async Task PublishedShortTtlIsStillReported() {
            DnsTtlAnalysis analysis = Analysis(resolverTtl: 60, authoritativeTtl: 60);

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.Contains(TooShort(analysis), m => m.StartsWith("A TTL 60", System.StringComparison.Ordinal));
        }

        [Fact]
        public async Task WithoutAnAuthoritativeAnswerOnlyTooLongIsJudged() {
            var analysis = new DnsTtlAnalysis {
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(type switch {
                    DnsRecordType.A => new[] { Answer(DnsRecordType.A, "192.0.2.10", 71) },
                    DnsRecordType.NS => new[] { Answer(DnsRecordType.NS, "ns1.example.net", 172800) },
                    _ => System.Array.Empty<DnsAnswer>()
                }),
                AuthoritativeTtlOverride = (_, _) => Task.FromResult<int?>(null)
            };

            await analysis.Analyze("example.com", new InternalLogger());

            Assert.False(analysis.TtlsFromAuthoritativeServers);
            Assert.Empty(TooShort(analysis));
            Assert.Contains(analysis.Assessments, a => a.Code == TtlCodes.TooLong);
        }
    }
}
