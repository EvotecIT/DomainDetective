using System.IO;
using System.IO.Compression;
using System.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Tests {
    public class TestDmarcReportParser {
        [Fact]
        public void ParseMultipleXmlEntries() {
            string zipPath = Path.GetTempFileName();
            File.Delete(zipPath);
            using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create)) {
                archive.CreateEntryFromFile(Path.Combine("Data", "dmarc1.xml"), "dmarc1.xml");
                archive.CreateEntryFromFile(Path.Combine("Data", "dmarc2.xml"), "dmarc2.xml");
            }

            var results = DmarcReportParser.ParseZip(zipPath).ToList();

            File.Delete(zipPath);

            Assert.Equal(3, results.Count);

            var exampleCom = results.First(r => r.Domain == "example.com");
            Assert.Equal(1, exampleCom.PassCount);
            Assert.Equal(1, exampleCom.FailCount);

            var exampleNet = results.First(r => r.Domain == "example.net");
            Assert.Equal(0, exampleNet.PassCount);
            Assert.Equal(1, exampleNet.FailCount);

            var exampleOrg = results.First(r => r.Domain == "example.org");
            Assert.Equal(1, exampleOrg.PassCount);
            Assert.Equal(0, exampleOrg.FailCount);
        }
    }
}
