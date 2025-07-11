using System.Reflection;
using DomainDetective.Protocols;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    public class TestAlgorithmNameMapping {
        [Theory]
        [InlineData(5, "RSASHA1")]
        [InlineData(8, "RSASHA256")]
        [InlineData(253, "PRIVATEDNS")]
        public void MapsAlgorithmNumbersToNames(int value, string expected) {
            Assert.Equal(expected, DNSKeyAnalysis.AlgorithmName(value));
        }

        [Fact]
        public void ParseFunctionsReturnNames() {
            var converter = typeof(DnsSecConverter);
            var parseDs = converter.GetMethod("ParseDsRecord", BindingFlags.NonPublic | BindingFlags.Static)!;
            var ds = (DsRecordInfo)parseDs.Invoke(null, new object[] { "60485 8 2 ABCD" })!;
            Assert.Equal("RSASHA256", ds.Algorithm);

            var parseKey = converter.GetMethod("ParseDnsKey", BindingFlags.NonPublic | BindingFlags.Static)!;
            var key = (DnsKeyInfo)parseKey.Invoke(null, new object[] { "257 3 8 AAAA" })!;
            Assert.Equal("RSASHA256", key.Algorithm);

            var analysisType = typeof(DnsSecAnalysis);
            var parseSig = analysisType.GetMethod("ParseRrsig", BindingFlags.NonPublic | BindingFlags.Static)!;
            var sig = (RrsigInfo)parseSig.Invoke(null, new object[] { "DNSKEY 8 2 3600 1755665684 1750395284 2371 example.com. AAAA" })!;
            Assert.Equal("RSASHA256", sig.Algorithm);

            var mapAlg = converter.GetMethod("MapAlgorithmNumber", BindingFlags.NonPublic | BindingFlags.Static)!;
            var mapped = (string)mapAlg.Invoke(null, new object[] { 8 })!;
            Assert.Equal("RSASHA256", mapped);
        }
    }
}