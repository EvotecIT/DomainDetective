using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestEmptyHealthCheckTypes {
        [Fact]
        public async Task VerifyWithEmptyHealthCheckTypesReturns() {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.Verify("example.com", Array.Empty<HealthCheckType>());
            Assert.False(healthCheck.IsPublicSuffix);
        }
    }
}
