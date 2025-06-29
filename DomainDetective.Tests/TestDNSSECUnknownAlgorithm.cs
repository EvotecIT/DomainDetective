using System.Reflection;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecUnknownAlgorithm {
        [Fact]
        public void UnknownAlgorithmNumberIsParsed() {
            var method = typeof(DnsSecAnalysis).GetMethod("AlgorithmNumber", BindingFlags.NonPublic | BindingFlags.Static)!;
            int value = (int)method.Invoke(null, new object[] { "99" })!;
            Assert.Equal(99, value);
        }
    }
}
