using System.IO;
using System.IO.Compression;
using System.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Tests;

public class TestDmarcReportParser {
    private static byte[] CreateZip(string xml) {
        using var ms = new MemoryStream();
        using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true)) {
            var entry = archive.CreateEntry("report.xml");
            using var writer = new StreamWriter(entry.Open());
            writer.Write(xml);
        }
        return ms.ToArray();
    }

    [Fact]
    public void ReleasesHandleAfterParsing() {
        const string xml = "<feedback><record><identifiers><header_from>example.com</header_from></identifiers><row><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record></feedback>";
        var bytes = CreateZip(xml);
        var file = Path.GetTempFileName();
        File.WriteAllBytes(file, bytes);
        try {
            var results = DmarcReportParser.ParseZip(file).ToList();
            Assert.Single(results);
            using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        } finally {
            File.Delete(file);
        }
    }

    [Fact]
    public void ReleasesHandleOnFailure() {
        const string xml = "<invalid"; // malformed xml
        var bytes = CreateZip(xml);
        var file = Path.GetTempFileName();
        File.WriteAllBytes(file, bytes);
        try {
            Assert.ThrowsAny<System.Xml.XmlException>(() => DmarcReportParser.ParseZip(file).ToList());
            using (File.Open(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
        } finally {
            File.Delete(file);
        }
    }
}
