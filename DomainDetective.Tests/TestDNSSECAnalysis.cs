using DomainDetective;
using DomainDetective.Protocols;

namespace DomainDetective.Tests {
    public class TestDnssecAnalysis {
        [Fact]
        public async Task ValidateDnssecForDomain() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("cloudflare.com", [HealthCheckType.DNSSEC]);

            Assert.NotEmpty(healthCheck.DnsSecAnalysis.DnsKeys);
            Assert.True(healthCheck.DnsSecAnalysis.AuthenticData);
            Assert.True(healthCheck.DnsSecAnalysis.DsAuthenticData);
            Assert.True(healthCheck.DnsSecAnalysis.DsMatch);
            Assert.True(healthCheck.DnsSecAnalysis.ChainValid);
            Assert.NotEmpty(healthCheck.DnsSecAnalysis.DsTtls);
            Assert.NotEmpty(healthCheck.DnsSecAnalysis.Rrsigs);
            Assert.NotEqual(0, healthCheck.DnsSecAnalysis.RootKeyTag);
            Assert.Empty(healthCheck.DnsSecAnalysis.MismatchSummary);
        }

        [Fact]
        public async Task ValidateDnssecChainFailure() {
            var healthCheck = new DomainHealthCheck { Verbose = false };
            await healthCheck.Verify("dnssec-failed.org", [HealthCheckType.DNSSEC]);

            Assert.False(healthCheck.DnsSecAnalysis.ChainValid);
            Assert.NotEmpty(healthCheck.DnsSecAnalysis.MismatchSummary);
        }

        [Theory]
        [InlineData(0, "DELETE")]
        [InlineData(1, "RSAMD5")]
        [InlineData(2, "DH")]
        [InlineData(3, "DSA")]
        [InlineData(4, "ECC")]
        [InlineData(5, "RSASHA1")]
        [InlineData(6, "DSANSEC3SHA1")]
        [InlineData(7, "RSASHA1NSEC3SHA1")]
        [InlineData(8, "RSASHA256")]
        [InlineData(9, "RESERVED")]
        [InlineData(10, "RSASHA512")]
        [InlineData(11, "RESERVED")]
        [InlineData(12, "ECCGOST")]
        [InlineData(13, "ECDSAP256SHA256")]
        [InlineData(14, "ECDSAP384SHA384")]
        [InlineData(15, "ED25519")]
        [InlineData(16, "ED448")]
        [InlineData(17, "SM2SM3")]
        [InlineData(23, "ECC-GOST12")]
        [InlineData(252, "INDIRECT")]
        [InlineData(253, "PRIVATEDNS")]
        [InlineData(254, "PRIVATEOID")]
        [InlineData(255, "RESERVED")]
        public void AlgorithmNumbersMapToNames(int value, string expected) {
            Assert.Equal(expected, DNSKeyAnalysis.AlgorithmName(value));
        }
    }}