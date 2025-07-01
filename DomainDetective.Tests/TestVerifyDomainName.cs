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

        [Fact]
        public async Task VerifyAcceptsUnicodeDomain() {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.VerifySPF("bücher.de");
        }

        [Fact]
        public async Task VerifyThrowsIfLabelTooLong() {
            var healthCheck = new DomainHealthCheck();
            var domain = new string('a', 64) + ".com";
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await healthCheck.VerifySPF(domain));
        }
    }
}
