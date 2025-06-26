using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestPortValidation {
        [Fact]
        public async Task CheckOpenRelayHostThrowsForTooHighPort() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
                await healthCheck.CheckOpenRelayHost("example.com", 65536));
        }

        [Fact]
        public async Task VerifyWebsiteCertificateThrowsForTooHighPort() {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
                await healthCheck.VerifyWebsiteCertificate("example.com", 70000));
        }
    }
}
