using DnsClientX;
using System.Reflection;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecRecordValidation {
        [Theory]
        [InlineData(DnsSecValidationStatus.Secure, true)]
        [InlineData(DnsSecValidationStatus.Insecure, false)]
        [InlineData(DnsSecValidationStatus.Bogus, false)]
        [InlineData(DnsSecValidationStatus.Indeterminate, false)]
        public async Task ValidateRecordUsesLocalDnsClientXStatus(DnsSecValidationStatus status, bool expected) {
            var response = new DnsResponse();
            typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                .SetValue(response, status);
            var analysis = new DnsSecAnalysis {
                QueryDnsResponseOverride = (_, _, _) => Task.FromResult(response)
            };
            bool result = await analysis.ValidateRecord("example.com", DnsRecordType.A);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(MultiResolverStrategy.FirstSuccess)]
        [InlineData(MultiResolverStrategy.FastestWins)]
        public void DnssecResolverHonorsConfiguredMultiResolverPolicy(MultiResolverStrategy strategy) {
            using var configuration = new DnsConfiguration {
                MultiResolverStrategy = strategy,
                MultiResolverMaxParallelism = 2
            };
            configuration.DnsEndpoints.Add(DnsEndpoint.Cloudflare);
            configuration.DnsEndpoints.Add(DnsEndpoint.Google);

            MultiResolverOptions validationOptions = DnsSecAnalysis.CreateResolverOptions(
                endpointCount: 4, dnsConfiguration: configuration, validateDnsSec: true);
            MultiResolverOptions metadataOptions = DnsSecAnalysis.CreateResolverOptions(
                endpointCount: 4, dnsConfiguration: configuration, validateDnsSec: false);

            Assert.Equal(strategy, validationOptions.Strategy);
            Assert.Equal(2, validationOptions.MaxParallelism);
            Assert.True(validationOptions.RequestDnsSec);
            Assert.True(validationOptions.ValidateDnsSec);
            Assert.Equal(strategy, metadataOptions.Strategy);
            Assert.Equal(2, metadataOptions.MaxParallelism);
            Assert.True(metadataOptions.RequestDnsSec);
            Assert.False(metadataOptions.ValidateDnsSec);
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
            Assert.False(analysis.ChainValid);
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

        [Theory]
        [InlineData(DnsSecValidationStatus.Secure, DnssecValidationStatus.Secure)]
        [InlineData(DnsSecValidationStatus.Insecure, DnssecValidationStatus.Insecure)]
        [InlineData(DnsSecValidationStatus.Bogus, DnssecValidationStatus.Bogus)]
        [InlineData(DnsSecValidationStatus.Indeterminate, DnssecValidationStatus.Indeterminate)]
        [InlineData(DnsSecValidationStatus.NotRequested, DnssecValidationStatus.NotChecked)]
        public void UsesDnsClientXValidationStatus(DnsSecValidationStatus source, DnssecValidationStatus expected) {
            Assert.Equal(expected, DnsSecAnalysis.MapValidationStatus(source));
        }
    }
}
