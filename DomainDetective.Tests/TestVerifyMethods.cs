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
            object[] args;
            if (parameters.Length == 2) {
                args = new object[] { "com", default(System.Threading.CancellationToken) };
            } else {
                var port = PortHelper.GetFreePort();
                args = new object[] { "com", port, default(System.Threading.CancellationToken) };
                PortHelper.ReleasePort(port);
            }
            var task = (Task)method.Invoke(hc, args)!;
            await task;
            Assert.True(hc.IsPublicSuffix);
        }
    }
}
