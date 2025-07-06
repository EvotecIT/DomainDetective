using System;
using DnsClientX;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestDomainHealthCheckConstructor {
        [Fact]
        public void ConstructorDefaultsToSystemEndpoint() {
            var healthCheck = new DomainHealthCheck(default);
            Assert.Equal(DnsEndpoint.System, healthCheck.DnsEndpoint);
        }
    }
}
