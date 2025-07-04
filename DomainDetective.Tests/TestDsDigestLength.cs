using System.Reflection;

namespace DomainDetective.Tests {
    public class TestDsDigestLength {
        [Fact]
        public void InvalidDigestLengthReturnsFalse() {
            var method = typeof(DnsSecAnalysis).GetMethod("IsDsDigestLengthValid", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { "2371 ECDSAP256SHA256 2 abcd" });
            Assert.False(result);
        }

        [Fact]
        public void ValidDigestLengthReturnsTrue() {
            var method = typeof(DnsSecAnalysis).GetMethod("IsDsDigestLengthValid", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { "2371 ECDSAP256SHA256 2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
            Assert.True(result);
        }

        [Fact]
        public void ValidSha1DigestLengthReturnsTrue() {
            var method = typeof(DnsSecAnalysis).GetMethod("IsDsDigestLengthValid", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { "2371 ECDSAP256SHA256 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
            Assert.True(result);
        }

        [Fact]
        public void ValidSha384DigestLengthReturnsTrue() {
            var method = typeof(DnsSecAnalysis).GetMethod("IsDsDigestLengthValid", BindingFlags.NonPublic | BindingFlags.Static)!;
            bool result = (bool)method.Invoke(null, new object[] { "2371 ECDSAP256SHA256 4 " + new string('a', 96) });
            Assert.True(result);
        }
    }
}
