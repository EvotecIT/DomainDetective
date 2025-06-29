using System;
using System.Reflection;
using Xunit;

namespace DomainDetective.Tests {
    public class TestRrsigParsing {
        [Fact]
        public void ParseRrsigRecord() {
            string record = "DNSKEY ECDSAP256SHA256 2 3600 1755665684 1750395284 2371 cloudflare.com. cttiL9pyC8QvCXsG6x3lDaix7y9NRiNY2A+8YovhAbmpRvuEGChMSSYific7AJQwcvqjj3NPtDIjTaKN9y370g==";
            var method = typeof(DnsSecAnalysis).GetMethod("ParseRrsig", BindingFlags.NonPublic | BindingFlags.Static)!;
            var info = (RrsigInfo)method.Invoke(null, new object[] { record })!;
            Assert.Equal(2371, info.KeyTag);
            Assert.Equal("ECDSAP256SHA256", info.Algorithm);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1750395284), info.Inception);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1755665684), info.Expiration);
        }
    }
}
