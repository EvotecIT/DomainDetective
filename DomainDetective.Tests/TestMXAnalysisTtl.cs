using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    /// <summary>
    /// TTL findings must not depend on how long a caching resolver has held an answer: the same zone has to give the
    /// same findings on every run.
    /// </summary>
    public class TestMXAnalysisTtl {
        private const string Host = "mail.example.com";

        private static DnsAnswer Answer(DnsRecordType type, string data, int ttl) => new() { Type = type, DataRaw = data, TTL = ttl };

        // A caching resolver: the same records, with the time each has left in the cache.
        private static MXAnalysis Analysis(int resolverATtl, int resolverAaaaTtl, int authoritativeATtl, int authoritativeAaaaTtl, bool authoritativeAnswers = true) {
            return new MXAnalysis {
                Subject = "example.com",
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(type switch {
                    DnsRecordType.A when name == Host => new[] { Answer(DnsRecordType.A, "192.0.2.10", resolverATtl) },
                    DnsRecordType.AAAA when name == Host => new[] { Answer(DnsRecordType.AAAA, "2001:db8::10", resolverAaaaTtl) },
                    _ => System.Array.Empty<DnsAnswer>()
                }),
                AuthoritativeQueryOverride = (name, type) => Task.FromResult<DnsAnswer[]?>(!authoritativeAnswers ? null : type switch {
                    DnsRecordType.MX => new[] { Answer(DnsRecordType.MX, "10 " + Host, 3600) },
                    DnsRecordType.A => new[] { Answer(DnsRecordType.A, "192.0.2.10", authoritativeATtl) },
                    DnsRecordType.AAAA => new[] { Answer(DnsRecordType.AAAA, "2001:db8::10", authoritativeAaaaTtl) },
                    _ => System.Array.Empty<DnsAnswer>()
                })
            };
        }

        private static List<DnsAnswer> ResolverMx(int ttl) => new() { Answer(DnsRecordType.MX, "10 " + Host, ttl) };

        private static string[] TtlFindings(MXAnalysis analysis)
            => analysis.Assessments.Where(static a => a.Code is MxCodes.TargetTtlNonUniform or MxCodes.TtlNonUniform).Select(static a => a.Code + "@" + a.Target).ToArray();

        [Fact]
        public async Task CountdownInTheResolverCacheRaisesNoFinding() {
            // Published with equal TTLs; the resolver cached A earlier than AAAA, so their remaining TTLs differ.
            MXAnalysis analysis = Analysis(resolverATtl: 277, resolverAaaaTtl: 300, authoritativeATtl: 300, authoritativeAaaaTtl: 300);

            await analysis.AnalyzeMxRecords(ResolverMx(3123), new InternalLogger());

            Assert.Empty(TtlFindings(analysis));
            Assert.True(analysis.TtlsFromAuthoritativeServers);
            Assert.True(analysis.MxTtlUniform);
            // The configured TTL, not what the resolver had left.
            Assert.Equal(3600, analysis.MinMxTtl);
            Assert.Equal(new[] { 3600 }, analysis.MxRecordTtls);
        }

        [Fact]
        public async Task RunsMinutesApartGiveTheSameFindings() {
            MXAnalysis first = Analysis(resolverATtl: 300, resolverAaaaTtl: 300, authoritativeATtl: 300, authoritativeAaaaTtl: 300);
            MXAnalysis later = Analysis(resolverATtl: 12, resolverAaaaTtl: 251, authoritativeATtl: 300, authoritativeAaaaTtl: 300);

            await first.AnalyzeMxRecords(ResolverMx(3600), new InternalLogger());
            await later.AnalyzeMxRecords(ResolverMx(1711), new InternalLogger());

            Assert.Equal(first.Assessments.Select(static a => a.Code + "|" + a.Message), later.Assessments.Select(static a => a.Code + "|" + a.Message));
            Assert.Equal(first.MinMxTtl, later.MinMxTtl);
        }

        [Fact]
        public async Task PublishedDifferenceIsStillReported() {
            MXAnalysis analysis = Analysis(resolverATtl: 300, resolverAaaaTtl: 300, authoritativeATtl: 300, authoritativeAaaaTtl: 3600);

            await analysis.AnalyzeMxRecords(ResolverMx(3600), new InternalLogger());

            Assert.Equal(new[] { MxCodes.TargetTtlNonUniform + "@" + Host }, TtlFindings(analysis));
        }

        [Fact]
        public async Task WithoutAnAuthoritativeAnswerTtlsAreNotCompared() {
            MXAnalysis analysis = Analysis(resolverATtl: 277, resolverAaaaTtl: 300, authoritativeATtl: 0, authoritativeAaaaTtl: 0, authoritativeAnswers: false);

            await analysis.AnalyzeMxRecords(ResolverMx(3123), new InternalLogger());

            Assert.Empty(TtlFindings(analysis));
            Assert.False(analysis.TtlsFromAuthoritativeServers);
            // Existing properties keep the resolver's view when nothing better is available.
            Assert.Equal(3123, analysis.MinMxTtl);
        }

        [Fact]
        public async Task FixedAnswersAreTreatedAsPublished() {
            // Replays and tests answer through QueryDnsOverride with fixed TTLs; those are compared as published.
            var analysis = new MXAnalysis {
                Subject = "example.com",
                DnsConfiguration = new DnsConfiguration(),
                QueryDnsOverride = (name, type) => Task.FromResult(type switch {
                    DnsRecordType.A when name == Host => new[] { Answer(DnsRecordType.A, "192.0.2.10", 300) },
                    DnsRecordType.AAAA when name == Host => new[] { Answer(DnsRecordType.AAAA, "2001:db8::10", 3600) },
                    _ => System.Array.Empty<DnsAnswer>()
                })
            };

            await analysis.AnalyzeMxRecords(ResolverMx(3600), new InternalLogger());

            Assert.True(analysis.TtlsFromAuthoritativeServers);
            Assert.Equal(new[] { MxCodes.TargetTtlNonUniform + "@" + Host }, TtlFindings(analysis));
        }
    }
}
