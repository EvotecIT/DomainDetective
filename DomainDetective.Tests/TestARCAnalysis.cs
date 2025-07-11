using System.IO;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestARCAnalysis {
        [Fact]
        public async Task ValidArcChain() {
            var raw = File.ReadAllText("Data/arc-valid.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.True(result.ValidChain);
        }

        [Fact]
        public async Task InvalidArcChain() {
            var raw = File.ReadAllText("Data/arc-invalid.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.False(result.ValidChain);
        }

        [Fact]
        public async Task MissingSignatureInvalidatesChain() {
            var raw = File.ReadAllText("Data/arc-missing-sig.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.False(result.ValidChain);
        }

        [Fact]
        public async Task EmptySignatureInvalidatesChain() {
            var raw = File.ReadAllText("Data/arc-empty-sig.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.False(result.ValidChain);
        }

        [Fact]
        public async Task OutOfOrderChainIsInvalid() {
            var raw = File.ReadAllText("Data/arc-out-of-order.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.False(result.ValidChain);
        }

        [Fact]
        public async Task RfcExampleIsValid() {
            var raw = File.ReadAllText("Data/arc-rfc-example.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.True(result.ValidChain);
        }
    }
}
