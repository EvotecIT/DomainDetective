using System.IO;
using Xunit;

namespace DomainDetective.Tests {
    public class TestParserSizeLimits {
        [Fact]
        public void TlsRptReportParser_ThrowsWhenMaxUncompressedExceeded() {
            using var ms = new MemoryStream(new byte[1024]);
            Assert.Throws<IOException>(() => TlsRptReportParser.Parse(ms, "report.json", maxUncompressedBytes: 100));
        }

        [Fact]
        public void DmarcReportParser_ThrowsWhenMaxUncompressedExceeded() {
            using var ms = new MemoryStream(new byte[1024]);
            Assert.Throws<IOException>(() => DmarcReportParser.Parse(ms, "report.xml", validationMessages: null, maxUncompressedBytes: 100));
        }
    }
}

