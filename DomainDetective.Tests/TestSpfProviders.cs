using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSpfProviders {
        [Fact]
        public async Task DetectsCommonIncludeProviders() {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all");
            var providers = hc.SpfAnalysis.SpfPartAnalyses.Where(p => !string.IsNullOrWhiteSpace(p.Provider)).Select(p => p.Provider).Distinct().ToArray();
            Assert.Contains("Google Workspace", providers);
            Assert.Contains("Microsoft 365", providers);
        }

        [Fact]
        public async Task DetectsSendersFromAandInclude() {
            var hc = new DomainDetective.DomainHealthCheck();
            await hc.CheckSPF("v=spf1 a:sendgrid.net include:_spf.mailgun.org include:spf.sparkpostmail.com -all");
            var providers = hc.SpfAnalysis.SpfPartAnalyses.Where(p => !string.IsNullOrWhiteSpace(p.Provider)).Select(p => p.Provider).Distinct().ToArray();
            Assert.Contains("SendGrid", providers);
            Assert.Contains("Mailgun", providers);
            Assert.Contains("SparkPost", providers);
        }
    }
}

