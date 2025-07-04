using DnsClientX;
using System.Collections.Generic;
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

        [Fact]
        public async Task HostNameIsValidated() {
            var name = new string('a', 56) + "._smimecert.example.com";
            var record = "3 1 1 " + new string('A', 64);
            var analysis = new SMIMEAAnalysis();
            await analysis.AnalyzeSMIMEARecords(new[] { new DnsAnswer { Name = name, DataRaw = record, Type = DnsRecordType.SMIMEA } }, new InternalLogger());
            Assert.True(analysis.AnalysisResults[0].ValidServiceAndProtocol);
        }

        [Fact]
        public async Task InvalidHostNameTriggersWarning() {
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var record = "3 1 1 " + new string('A', 64);
            await new SMIMEAAnalysis().AnalyzeSMIMEARecords(new[] {
                new DnsAnswer { Name = "abcd._smimecert._tcp.example.com", DataRaw = record, Type = DnsRecordType.SMIMEA }
            }, logger);
            Assert.Contains(warnings, w => w.FullMessage.Contains("SMIMEA host name"));
        }
    }
}
