using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestDnsblIpv6 {
        [Fact]
        public async Task Ipv6AddressReversedNibble() {
            const string address = "2001:db8::1";
            var healthCheck = new DomainHealthCheck();
            healthCheck.DNSBLAnalysis.ClearDNSBL();
            healthCheck.DNSBLAnalysis.AddDNSBL("example.test");
            await healthCheck.CheckDNSBL(address);

            var record = healthCheck.DNSBLAnalysis.Results[address].DNSBLRecords.First();
            var expected = string.Join(".", string.Concat(IPAddress.Parse(address).GetAddressBytes().Select(b => b.ToString("x2"))).Reverse());
            Assert.Equal(expected, record.IPAddress);
            Assert.Equal(address, record.OriginalIPAddress);
        }

        [Fact]
        public async Task Ipv6AddressFormsFqdnCorrectly() {
            const string address = "2001:db8::2";
            var healthCheck = new DomainHealthCheck();
            healthCheck.DNSBLAnalysis.ClearDNSBL();
            healthCheck.DNSBLAnalysis.AddDNSBL("example.test");
            await healthCheck.CheckDNSBL(address);

            var record = healthCheck.DNSBLAnalysis.Results[address].DNSBLRecords.First();
            var nibble = string.Join(".", string.Concat(IPAddress.Parse(address).GetAddressBytes().Select(b => b.ToString("x2"))).Reverse());
            Assert.Equal($"{nibble}.example.test", record.FQDN);
        }
    }
}
