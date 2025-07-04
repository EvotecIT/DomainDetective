using DomainDetective;
using System.Linq;
using System.Net;

namespace DomainDetective.Tests {
    public class TestIPAddressExtensions {
        [Fact]
        public void Ipv4PtrFormat() {
            var ip = IPAddress.Parse("1.2.3.4");
            Assert.Equal("4.3.2.1", ip.ToPtrFormat());
        }

        [Fact]
        public void Ipv6PtrFormat() {
            var ip = IPAddress.IPv6Loopback;
            var expected = string.Join(
                ".",
                ip
                    .GetAddressBytes()
                    .SelectMany(b => new[] { (b >> 4) & 0xF, b & 0xF })
                    .Select(n => n.ToString("x"))
                    .Reverse());
            Assert.Equal(expected, ip.ToPtrFormat());
        }
    }
}