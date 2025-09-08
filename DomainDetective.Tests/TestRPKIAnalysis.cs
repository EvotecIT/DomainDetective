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

        [Fact]
        public async Task DowngradesFailuresToWarnings()
        {
            var analysis = new RPKIAnalysis
            {
                DnsConfiguration = new DnsConfiguration(),
                // Return an invalid IP-like token so the internal HttpClient URI construction fails
                // and the code path logs a warning via RpkiCodes.QueryFailed.
                QueryDnsOverride = (n, t) => t == DnsRecordType.A
                    ? Task.FromResult(new[] { new DnsAnswer { DataRaw = "%%%" } })
                    : Task.FromResult(Array.Empty<DnsAnswer>())
            };

            var logger = new InternalLogger();
            await analysis.Analyze("example.com", logger);

            // Pipeline should continue and produce a result with Valid = false
            var res = Assert.Single(analysis.Results);
            Assert.Equal("%%%", res.IpAddress);
            Assert.False(res.Valid);

            // Ensure the downgrade to Warning is captured as an assessment with the correct code
            Assert.Contains(analysis.Assessments, a => a.Code == RpkiCodes.QueryFailed && a.Severity == AssessmentSeverity.Warning);
            Assert.DoesNotContain(analysis.Assessments, a => a.Code == RpkiCodes.QueryFailed && a.Severity == AssessmentSeverity.Error);
        }
    }
}
