using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestPublicSuffix {
        [Theory]
        [InlineData("com")]
        [InlineData("co.uk")]
        [InlineData("net")]
        public async Task RecognizesSuffix(string domain) {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.VerifySPF(domain);
            Assert.True(healthCheck.IsPublicSuffix);
        }

        [Theory]
        [InlineData("example.com")]
        [InlineData("example.co.uk")]
        [InlineData("microsoft.net")]
        public async Task RecognizesRegistrable(string domain) {
            var healthCheck = new DomainHealthCheck();
            await healthCheck.VerifySPF(domain);
            Assert.False(healthCheck.IsPublicSuffix);
        }
    }
}
