using System.Reflection;

namespace DomainDetective.Tests {
    public class TestDnssecInvalidDs {
        [Fact]
        public void InvalidDsDigestReturnsFalse() {
            var dnskey = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==";
            var dsRecord = "2371 ECDSAP256SHA256 2 c988ec423e3880eb8dd8a46fe06ca230ee23f35b578d64e78b29c3e1c83d245z";
            var method = typeof(DNSSecAnalysis).GetMethod("VerifyDsMatch", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { dnskey, dsRecord, "example.com" });
            Assert.False(result);
        }

        [Fact]
        public void MismatchedDsDigestReturnsFalse() {
            var dnskey = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==";
            var dsRecord = "2371 ECDSAP256SHA256 2 c988ec423e3880eb8dd8a46fe06ca230ee23f35b578d64e78b29c3e1c83d246";
            var method = typeof(DNSSecAnalysis).GetMethod("VerifyDsMatch", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { dnskey, dsRecord, "example.com" });
            Assert.False(result);
        }
    }
}