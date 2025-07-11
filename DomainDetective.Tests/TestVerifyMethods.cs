using DomainDetective;
using System.Reflection;
using System.Threading.Tasks;

namespace DomainDetective.Tests {
    public class TestVerifyMethods {
        [Theory]
        [InlineData("VerifyDMARC")]
        [InlineData("VerifyDNSSEC")]
        [InlineData("VerifyCAA")]
        [InlineData("VerifyMX")]
        [InlineData("VerifyNS")]
        [InlineData("VerifySOA")]
        [InlineData("VerifyDNSBL")]
        [InlineData("VerifyOpenRelay")]
        public async Task PublicSuffixSet(string methodName) {
            var hc = new DomainHealthCheck();
            var method = typeof(DomainHealthCheck).GetMethod(methodName)!;
            var parameters = method.GetParameters();
            object[] args = parameters.Length == 2
                ? new object[] { "com", default(System.Threading.CancellationToken) }
                : new object[] { "com", 25, default(System.Threading.CancellationToken) };
            var task = (Task)method.Invoke(hc, args)!;
            await task;
            Assert.True(hc.IsPublicSuffix);
        }
    }
}
