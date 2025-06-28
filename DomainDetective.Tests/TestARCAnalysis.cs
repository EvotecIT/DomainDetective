using System.IO;

namespace DomainDetective.Tests {
    public class TestARCAnalysis {
        [Fact]
        public void ValidArcChain() {
            var raw = File.ReadAllText("Data/arc-valid.txt");
            var hc = new DomainHealthCheck();
            var result = hc.VerifyARC(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.True(result.ValidChain);
        }

        [Fact]
        public void InvalidArcChain() {
            var raw = File.ReadAllText("Data/arc-invalid.txt");
            var hc = new DomainHealthCheck();
            var result = hc.VerifyARC(raw);
            Assert.True(result.ArcHeadersFound);
            Assert.False(result.ValidChain);
        }
    }
}
