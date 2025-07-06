using DnsClientX;
using DomainDetective;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnsConfigurationDefaults {
        [Fact]
        public void DefaultEndpointIsSystem() {
            var config = new DnsConfiguration();
            Assert.Equal(DnsEndpoint.System, config.DnsEndpoint);
        }
    }
}
