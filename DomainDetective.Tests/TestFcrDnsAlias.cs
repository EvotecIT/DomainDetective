using Xunit;

namespace DomainDetective.Tests {
    public class TestFcrDnsAlias {
        [Fact]
        public void AliasReturnsSameInstance() {
            var healthCheck = new DomainHealthCheck();
            Assert.Same(healthCheck.FcrDnsAnalysis, healthCheck.FCRDNSAnalysis);
        }
    }
}
