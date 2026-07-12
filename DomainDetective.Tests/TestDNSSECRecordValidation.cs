using DnsClientX;
using System.Reflection;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecRecordValidation {
        [Theory]
        [InlineData("cloudflare.com", DnsRecordType.A, true)]
        [InlineData("dnssec-failed.org", DnsRecordType.A, false)]
        public async Task ValidateRecordForZone(string domain, DnsRecordType type, bool expected) {
            var analysis = new DnsSecAnalysis();
            bool result = await analysis.ValidateRecord(domain, type);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("2371 ECDSAP256SHA256 1 9bacd9689f3c9eceb62e2e533ca7a87669f7e58b")]
        [InlineData("2371 ECDSAP256SHA256 2 c988ec423e3880eb8dd8a46fe06ca230ee23f35b578d64e78b29c3e1c83d245a")]
        [InlineData("2371 ECDSAP256SHA256 4 da0163a25f5219588189215e44b444102848e853ae6a78b96ae5c75a4df7c90bd1fbcd5761bd2aa4a477c5fe0b514312")]
        public void SampleDsRecordsHaveValidLength(string record) {
            var method = typeof(DnsSecAnalysis).GetMethod("IsDsDigestLengthValid", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { record })!;
            Assert.True(result);
        }

        [Fact]
        public async Task AnalysisWithoutDsRecordsSetsDsMatchFalse() {
            var analysis = new DnsSecAnalysis {
                QueryDnsResponseOverride = (_, type, _) => Task.FromResult(type == DnsRecordType.DNSKEY
                    ? new DnsResponse {
                        AuthenticData = true,
                        Answers = new[] {
                            new DnsAnswer { Type = DnsRecordType.DNSKEY, DataRaw = "257 3 13 AQID" }
                        }
                    }
                    : new DnsResponse { AuthenticData = true, Answers = System.Array.Empty<DnsAnswer>() })
            };
            await analysis.Analyze("cisco.com", null!);
            Assert.False(analysis.DsMatch);
            Assert.Empty(analysis.DsRecords);
        }

        [Fact]
        public async Task RecordAnalysisAuthenticatesTheRequestedRrset() {
            DnsRecordType? subjectType = null;
            var analysis = new DnsSecAnalysis {
                QueryDnsResponseOverride = (name, type, _) => {
                    if (name == "_443._tcp.example.com") {
                        subjectType ??= type;
                    }
                    return Task.FromResult(new DnsResponse {
                        AuthenticData = type != DnsRecordType.TLSA,
                        Answers = System.Array.Empty<DnsAnswer>()
                    });
                }
            };

            await analysis.AnalyzeRecord("_443._tcp.example.com", DnsRecordType.TLSA, null!);

            Assert.Equal(DnsRecordType.TLSA, subjectType);
            Assert.False(analysis.SubjectAuthenticData);
            Assert.NotEqual(DnssecValidationStatus.Secure, analysis.ValidationStatus);
        }
    }
}
