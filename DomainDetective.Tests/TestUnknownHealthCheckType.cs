using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestUnknownHealthCheckType {
        [Fact]
        public async Task VerifyUnknownHealthCheckTypeThrows() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<NotSupportedException>(async () =>
                await healthCheck.Verify("example.com", new[] { (HealthCheckType)999 }));
        }
    }
}