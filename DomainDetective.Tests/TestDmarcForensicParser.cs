using DomainDetective.Reports;
using System;
using System.IO;
using System.Linq;
using Xunit;

namespace DomainDetective.Tests {
    public class TestDmarcForensicParser {
        [Fact]
        public void ParseSampleForensic() {
            var b64 = File.ReadAllText("Data/dmarc_forensic.b64");
            var tmp = Path.GetTempFileName();
            File.WriteAllBytes(tmp, Convert.FromBase64String(b64));
            var reports = DmarcForensicParser.ParseZip(tmp).ToList();
            File.Delete(tmp);
            Assert.Single(reports);
            var report = reports[0];
            Assert.Equal("192.0.2.1", report.SourceIp);
            Assert.Equal("spoof@example.com", report.OriginalMailFrom);
            Assert.Equal("victim@example.net", report.OriginalRcptTo);
            Assert.Equal("example.com", report.HeaderFrom);
            Assert.True(report.ArrivalDate.HasValue);
        }
    }
}
