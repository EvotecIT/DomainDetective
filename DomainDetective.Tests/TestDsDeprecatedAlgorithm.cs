using DomainDetective.Protocols;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDsDeprecatedAlgorithm {
        [Theory]
        [InlineData(1)]
        [InlineData(3)]
        [InlineData(5)]
        [InlineData(6)]
        [InlineData(7)]
        [InlineData(12)]
        public void DetectsDeprecatedAlgorithms(int value) {
            Assert.True(DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(value));
        }

        [Theory]
        [InlineData(8)]
        [InlineData(13)]
        public void NonDeprecatedAlgorithmsReturnFalse(int value) {
            Assert.False(DNSKeyAnalysis.IsDeprecatedAlgorithmNumber(value));
        }
    }
}
