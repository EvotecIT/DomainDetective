using DomainDetective;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestVerifyDomainName {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public async Task VerifyThrowsIfDomainNullOrWhitespace(string? domain) {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await healthCheck.VerifySPF(domain));
        }
    }
}
