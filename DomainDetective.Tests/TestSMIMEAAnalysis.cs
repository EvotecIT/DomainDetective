using DnsClientX;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSMIMEAAnalysis {
        [Fact]
        public void QueryNameFollowsRfcExample() {
            var name = SMIMEAAnalysis.GetQueryName("hugh@example.com");
            Assert.Equal("c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com", name);
        }

        [Fact]
        public async Task AnalyzeRecordWorks() {
            var record = "3 1 1 " + new string('A', 64);
            var analysis = new SMIMEAAnalysis();
            await analysis.AnalyzeSMIMEARecords(new[] { new DnsAnswer { DataRaw = record } }, new InternalLogger());
            Assert.True(analysis.AnalysisResults[0].ValidSMIMEARecord);
        }
    }
}
