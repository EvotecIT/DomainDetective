using DomainDetective;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests {
    public class TestTlsRptJsonParser {
        [Fact]
        public void ParseSampleReport() {
            var summaries = TlsRptJsonParser.ParseReport(Path.Combine("Data", "tlsrpt.json")).ToList();
            Assert.Single(summaries);
            Assert.Equal("mx.example.com", summaries[0].MxHost);
            Assert.Equal(90, summaries[0].SuccessfulSessions);
            Assert.Equal(10, summaries[0].FailedSessions);
        }
    }
}
