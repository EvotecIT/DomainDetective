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
        public async Task SyntheticMultiInstanceHeadersHaveCompleteStructure() {
            // Includes synthetic signature values; this is structural evidence only.
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

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task FailedSealInvalidatesCompleteArcChain(bool hasLaterPassingSeal) {
            static string Set(int instance, string cv) =>
                $"ARC-Seal: i={instance}; cv={cv}; b=YWJj\r\n" +
                $"ARC-Message-Signature: i={instance}; b=YWJj\r\n" +
                $"ARC-Authentication-Results: i={instance}; mx.example; dkim=pass\r\n";

            string raw = Set(1, "none") + Set(2, "fail") + (hasLaterPassingSeal ? Set(3, "pass") : string.Empty);
            var healthCheck = new DomainHealthCheck();
            var analysis = await healthCheck.VerifyARCAsync(raw);

            Assert.True(analysis.ChainValidationFailed);
            Assert.False(analysis.ValidChain);
            Assert.Equal(ArcChainState.Invalid, analysis.ChainState);
            Assert.Contains(analysis.StructureIssues, issue => issue.Contains("cv=fail"));
            Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == ArcCodes.ChainValid);
        }
    }
}
