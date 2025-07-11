using DomainDetective;
using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestVerifyDomainNameNew {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public async Task VerifyDmarcThrowsIfDomainNullOrWhitespace(string? domain) {
            var healthCheck = new DomainHealthCheck();
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await healthCheck.VerifyDMARC(domain));
        }
    }
}
