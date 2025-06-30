using DomainDetective.Reports;
using System.IO;
using System.IO.Compression;
using System.Linq;

namespace DomainDetective.Tests {
    public class TestDmarcReportParser {
        [Fact]
        public void ParseZipWithMultipleFiles() {
            const string xml1 = "<feedback><record><row><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record><record><row><policy_evaluated><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>example.net</header_from></identifiers></record></feedback>";
            const string xml2 = "<feedback><record><row><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers></record><record><row><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row><identifiers><header_from>example.net</header_from></identifiers></record></feedback>";
            var zipPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".zip");
            try {
                using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create)) {
                    var e1 = archive.CreateEntry("report1.xml");
                    using (var writer = new StreamWriter(e1.Open())) {
                        writer.Write(xml1);
                    }
                    var e2 = archive.CreateEntry("report2.xml");
                    using (var writer = new StreamWriter(e2.Open())) {
                        writer.Write(xml2);
                    }
                }

                var summaries = DmarcReportParser.ParseZip(zipPath).ToList();
                Assert.Equal(2, summaries.Count);
                var exampleCom = summaries.First(s => s.Domain == "example.com");
                var exampleNet = summaries.First(s => s.Domain == "example.net");
                Assert.Equal(2, exampleCom.PassCount);
                Assert.Equal(0, exampleCom.FailCount);
                Assert.Equal(1, exampleNet.PassCount);
                Assert.Equal(1, exampleNet.FailCount);
            } finally {
                if (File.Exists(zipPath)) {
                    File.Delete(zipPath);
                }
            }
        }
    }
}
