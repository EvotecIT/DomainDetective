using System.Reflection;

namespace DomainDetective.Tests {
    public class TestDnsblReplyCodes {
        [Fact]
        public void HostkarmaMapping() {
            var method = typeof(DNSBLAnalysis).GetMethod("GetReplyCodeMeaning", BindingFlags.NonPublic | BindingFlags.Static)!;
            var result = (ValueTuple<bool, string>)method.Invoke(null, new object[] { "hostkarma.junkemailfilter.com", "127.0.0.2" });
            Assert.True(result.Item1);
            Assert.Equal("Blacklisted", result.Item2);
            var result2 = (ValueTuple<bool, string>)method.Invoke(null, new object[] { "hostkarma.junkemailfilter.com", "127.0.0.1" });
            Assert.False(result2.Item1);
            Assert.Equal("Whitelisted", result2.Item2);
        }
    }
}
