using System.Reflection;
using DomainDetective.Protocols;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDnssecUnknownAlgorithm {
        [Fact]
        public void UnknownAlgorithmNumberIsInvalid() {
            var method = typeof(DnsSecAnalysis).GetMethod("AlgorithmNumber", BindingFlags.NonPublic | BindingFlags.Static)!;
            int value = (int)method.Invoke(null, new object[] { "99" })!;
            Assert.Equal(0, value);
            Assert.False(DNSKeyAnalysis.IsValidAlgorithmNumber(value));
        }
    }
}
