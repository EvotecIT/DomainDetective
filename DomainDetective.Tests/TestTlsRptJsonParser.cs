using DomainDetective;
using System;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests {
    public class TestTlsRptJsonParser {
        [Fact]
        public void ParseSampleReport() {
            var summaries = TlsRptJsonParser.ParseReport("Data/tlsrpt.json").ToList();
            Assert.Single(summaries);
            Assert.Equal("mx.example.com", summaries[0].MxHost);
            Assert.Equal(90, summaries[0].SuccessfulSessions);
            Assert.Equal(10, summaries[0].FailedSessions);
        }

        [Fact]
        public void InvalidReportThrows() {
            Assert.Throws<FormatException>(() => TlsRptJsonParser.ParseReport("Data/tlsrpt-invalid.json").ToList());
        }
    }
}
