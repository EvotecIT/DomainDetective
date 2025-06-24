using DnsClientX;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecRecordValidation {
        [Theory]
        [InlineData("cloudflare.com", DnsRecordType.A, true)]
        [InlineData("dnssec-failed.org", DnsRecordType.A, false)]
        public async Task ValidateRecordForZone(string domain, DnsRecordType type, bool expected) {
            var analysis = new DNSSecAnalysis();
            bool result = await analysis.ValidateRecord(domain, type);
            Assert.Equal(expected, result);
        }
    }
}