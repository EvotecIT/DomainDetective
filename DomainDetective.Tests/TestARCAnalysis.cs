using System.IO;
using System.Threading.Tasks;
using DomainDetective;

namespace DomainDetective.Tests {
    public class TestARCAnalysis {
        [Fact]
        public async Task ValidArcChain() {
            var raw = File.ReadAllText("Data/arc-valid.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Valid, result.ChainState);
        }

        [Fact]
        public async Task ValidArcChainEmitsPositiveCodes() {
            var raw = File.ReadAllText("Data/arc-valid.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Contains(result.Assessments, a => a.Code == ArcCodes.ChainValid);
            Assert.Contains(result.Assessments, a => a.Code == ArcCodes.SealsIntact);
        }

        [Fact]
        public async Task InvalidArcChain() {
            var raw = File.ReadAllText("Data/arc-invalid.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Invalid, result.ChainState);
        }

        [Fact]
        public async Task MissingSignatureInvalidatesChain() {
            var raw = File.ReadAllText("Data/arc-missing-sig.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Invalid, result.ChainState);
        }

        [Fact]
        public async Task EmptySignatureInvalidatesChain() {
            var raw = File.ReadAllText("Data/arc-empty-sig.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Invalid, result.ChainState);
        }

        [Fact]
        public async Task OutOfOrderChainIsInvalid() {
            var raw = File.ReadAllText("Data/arc-out-of-order.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Invalid, result.ChainState);
        }

        [Fact]
        public async Task RfcExampleIsValid() {
            var raw = File.ReadAllText("Data/arc-rfc-example.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Valid, result.ChainState);
        }

        [Fact]
        public async Task MissingArcHeadersReturnMissingState() {
            var raw = File.ReadAllText("Data/sample-headers.txt");
            var hc = new DomainHealthCheck();
            var result = await hc.VerifyARCAsync(raw);
            Assert.Equal(ArcChainState.Missing, result.ChainState);
        }
    }
}
