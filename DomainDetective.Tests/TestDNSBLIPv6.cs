using System.Linq;
using System.Net;
using System.Reflection;
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
            var expected = string.Join(
                ".",
                IPAddress
                    .Parse(address)
                    .GetAddressBytes()
                    .SelectMany(b => new[] { b >> 4 & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());
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
            var nibble = string.Join(
                ".",
                IPAddress
                    .Parse(address)
                    .GetAddressBytes()
                    .SelectMany(b => new[] { b >> 4 & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());
            Assert.Equal($"{nibble}.example.test", record.FQDN);
        }

        [Fact]
        public async Task Ipv6LoopbackAddressChecks() {
            var address = IPAddress.IPv6Loopback.ToString();
            var healthCheck = new DomainHealthCheck();
            healthCheck.DNSBLAnalysis.ClearDNSBL();
            healthCheck.DNSBLAnalysis.AddDNSBL("example.test");
            await healthCheck.CheckDNSBL(address);

            var record = healthCheck.DNSBLAnalysis.Results[address].DNSBLRecords.First();
            var expected = string.Join(
                ".",
                IPAddress.IPv6Loopback
                    .GetAddressBytes()
                    .SelectMany(b => new[] { b >> 4 & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());
            Assert.Equal(expected, record.IPAddress);
        }

        [Fact]
        public void ConvertIpv6BlacklistedResults() {
            const string address = "2001:db8::dead";
            var analysis = new DNSBLAnalysis();
            var method = typeof(DNSBLAnalysis).GetMethod(
                "ConvertToResults",
                BindingFlags.NonPublic | BindingFlags.Instance)!;

            var nibble = string.Join(
                ".",
                IPAddress
                    .Parse(address)
                    .GetAddressBytes()
                    .SelectMany(b => new[] { b >> 4 & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());

            var record = new DNSBLRecord {
                IPAddress = nibble,
                OriginalIPAddress = address,
                FQDN = $"{nibble}.example.test",
                BlackList = "example.test",
                IsBlackListed = true,
                Answer = "127.0.0.2",
                ReplyMeaning = "Blacklisted",
            };

            method.Invoke(analysis, new object[] { address, new[] { record } });

            var result = analysis.Results[address];
            Assert.True(result.IsBlacklisted);
            Assert.Equal("Blacklisted", result.DNSBLRecords.First().ReplyMeaning);
        }

        [Fact]
        public void ConvertIpv6NotListedResults() {
            const string address = "2001:db8::beef";
            var analysis = new DNSBLAnalysis();
            var method = typeof(DNSBLAnalysis).GetMethod(
                "ConvertToResults",
                BindingFlags.NonPublic | BindingFlags.Instance)!;

            var nibble = string.Join(
                ".",
                IPAddress
                    .Parse(address)
                    .GetAddressBytes()
                    .SelectMany(b => new[] { b >> 4 & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());

            var record = new DNSBLRecord {
                IPAddress = nibble,
                OriginalIPAddress = address,
                FQDN = $"{nibble}.example.test",
                BlackList = "example.test",
                IsBlackListed = false,
                Answer = string.Empty,
                ReplyMeaning = string.Empty,
            };

            method.Invoke(analysis, new object[] { address, new[] { record } });

            var result = analysis.Results[address];
            Assert.False(result.IsBlacklisted);
            Assert.Empty(result.DNSBLRecords.First().ReplyMeaning);
        }
    }
}