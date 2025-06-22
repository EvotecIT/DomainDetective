using DomainDetective;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestTLSRPTAnalysis {
        [Fact]
        public async Task ParseValidTlsRptPolicy() {
            var record = "v=TLSRPTv1;rua=mailto:reports@example.com";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckTLSRPT(record);
            Assert.True(healthCheck.TLSRPTAnalysis.PolicyValid);
            Assert.Single(healthCheck.TLSRPTAnalysis.MailtoRua);
            Assert.Equal("reports@example.com", healthCheck.TLSRPTAnalysis.MailtoRua[0]);
        }

        [Fact]
        public async Task MissingRuaInvalidatesPolicy() {
            var record = "v=TLSRPTv1";
            var healthCheck = new DomainHealthCheck();
            await healthCheck.CheckTLSRPT(record);
            Assert.False(healthCheck.TLSRPTAnalysis.RuaDefined);
            Assert.False(healthCheck.TLSRPTAnalysis.PolicyValid);
        }
    }
}

