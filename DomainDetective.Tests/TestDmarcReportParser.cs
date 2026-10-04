using DomainDetective;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml.Schema;
using Xunit;

namespace DomainDetective.Tests;

public class TestDmarcReportParser {
    private const string V1Ns = "http://dmarc.org/dmarc-xml/0.1";
    private const string V2Ns = "http://dmarc.org/dmarc-xml/2.0";

    [Fact]
    public void ParseUnicodeDomain() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\"><record><identifiers><header_from>bücher.de</header_from></identifiers><row><source_ip>1.2.3.4</source_ip><policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record></feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        Assert.Single(report.Records);
        Assert.Equal("xn--bcher-kva.de", report.Records[0].HeaderFrom);
        Assert.Equal("1.2.3.4", report.Records[0].SourceIp);
    }

    [Fact]
    public void SummarizeFailures() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\">" +
            "<record><identifiers><header_from>example.com</header_from></identifiers><row><source_ip>1.2.3.4</source_ip><count>2</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf><disposition>reject</disposition></policy_evaluated></row></record>" +
            "<record><identifiers><header_from>example.org</header_from></identifiers><row><source_ip>5.6.7.8</source_ip><count>1</count><policy_evaluated><dkim>pass</dkim><spf>fail</spf><disposition>none</disposition></policy_evaluated></row></record>" +
            "</feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        var records = report.Records;
        var failures = records.GetFailureRecords().ToList();
        Assert.Single(failures);
        Assert.Equal("1.2.3.4", failures[0].SourceIp);
        Assert.Equal(2, failures[0].Count);

        var byIp = records.SummarizeFailuresByIp().Single();
        Assert.Equal("1.2.3.4", byIp.SourceIp);
        Assert.Equal(2, byIp.Count);

        var byHeaderFrom = records.SummarizeFailuresByHeaderFrom().Single();
        Assert.Equal("example.com", byHeaderFrom.HeaderFrom);
        Assert.Equal(2, byHeaderFrom.Count);
    }

    [Fact]
    public void ParseNegativeCountDefaultsToOne() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\">" +
            "<record><identifiers><header_from>example.com</header_from></identifiers><row><source_ip>1.2.3.4</source_ip><count>-5</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf><disposition>reject</disposition></policy_evaluated></row></record>" +
            "</feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        Assert.Single(report.Records);
        Assert.Equal(1, report.Records[0].Count);
    }

    [Fact]
    public void SummarizeByIpAggregatesCounts() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\">" +
            "<record><identifiers><header_from>a.com</header_from></identifiers><row><source_ip>1.1.1.1</source_ip><count>2</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf><disposition>reject</disposition></policy_evaluated></row></record>" +
            "<record><identifiers><header_from>b.com</header_from></identifiers><row><source_ip>1.1.1.1</source_ip><count>3</count><policy_evaluated><dkim>fail</dkim><spf>fail</spf><disposition>reject</disposition></policy_evaluated></row></record>" +
            "</feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        var summary = report.Records.SummarizeFailuresByIp().Single();
        Assert.Equal("1.1.1.1", summary.SourceIp);
        Assert.Equal(5, summary.Count);
    }

    [Fact]
    public void ParseZipWithoutXmlEntryReturnsNoRecords() {
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            archive.CreateEntry("readme.txt");
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        Assert.Empty(report.Records);
    }

    [Fact]
    public void InvalidXmlProducesValidationMessages() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\"><record><identifiers></identifiers><row><source_ip>1.2.3.4</source_ip><count>abc</count></row></record></feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var errors = new List<string>();
        var report = DmarcReportParser.Parse(tmp, errors);
        File.Delete(tmp);
        Assert.NotEmpty(errors);
        Assert.Equal(errors, report.ValidationMessages);
        Assert.Empty(report.Records);
    }

    [Fact]
    public void InvalidXmlThrowsWhenNoCollector() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\"><record><identifiers></identifiers><row><source_ip>1.2.3.4</source_ip><count>abc</count></row></record></feedback>"; 
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        Assert.Throws<XmlSchemaValidationException>(() => DmarcReportParser.Parse(tmp));
        File.Delete(tmp);
    }

    [Fact]
    public void UnknownNamespaceThrows() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"http://example.com/unknown\"/>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var ex = Assert.Throws<InvalidOperationException>(() => DmarcReportParser.Parse(tmp));
        Assert.Contains("Unknown DMARC namespace 'http://example.com/unknown'", ex.Message);
        File.Delete(tmp);
    }

    [Fact]
    public void ParseV2Namespace() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V2Ns + "\"><record><identifiers><header_from>v2.com</header_from></identifiers><row><source_ip>8.8.8.8</source_ip><policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record></feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        Assert.Single(report.Records);
        Assert.Equal("v2.com", report.Records[0].HeaderFrom);
    }

    [Fact]
    public void ParseSampleV1Reports() {
        var baseDir = Path.Combine(AppContext.BaseDirectory, "Reports");
        var xmlPath = Path.Combine(baseDir, "sample_v1.xml");
        var xmlBytes = File.ReadAllBytes(xmlPath);

        var gzPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".xml.gz");
        using (var file = File.Create(gzPath))
        using (var gz = new GZipStream(file, CompressionLevel.Optimal)) {
            gz.Write(xmlBytes, 0, xmlBytes.Length);
        }

        var zipPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("sample_v1.xml");
            using var entryStream = entry.Open();
            entryStream.Write(xmlBytes, 0, xmlBytes.Length);
        }

        var xmlReport = DmarcReportParser.Parse(xmlPath);
        var gzReport = DmarcReportParser.Parse(gzPath);
        var zipReport = DmarcReportParser.Parse(zipPath);

        Assert.Equal("example.com", xmlReport.PolicyPublished.Domain);
        Assert.Equal(xmlReport.PolicyPublished.Domain, gzReport.PolicyPublished.Domain);
        Assert.Equal(xmlReport.PolicyPublished.Domain, zipReport.PolicyPublished.Domain);

        using (var stream = File.OpenRead(zipPath)) {
            var streamReport = DmarcReportParser.Parse(stream, zipPath);
            Assert.Equal("example.com", streamReport.PolicyPublished.Domain);
        }

        File.Delete(gzPath);
        File.Delete(zipPath);
    }

    [Fact]
    public void ParseSampleV2PolicyExtensions() {
        var baseDir = Path.Combine(AppContext.BaseDirectory, "Reports");
        var path = Path.Combine(baseDir, "sample_v2.xml");
        var report = DmarcReportParser.Parse(path);
        Assert.Equal("example.net", report.PolicyPublished.Domain);
        Assert.Equal("reject", report.PolicyPublished.Np);
        Assert.Equal("1", report.PolicyPublished.Fo);
    }

    [Fact]
    public void RecordCountMatchesParsedRecords() {
        const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><feedback xmlns=\"" + V1Ns + "\">" +
            "<record><identifiers><header_from>a.com</header_from></identifiers><row><source_ip>1.1.1.1</source_ip><policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record>" +
            "<record><identifiers><header_from>b.com</header_from></identifiers><row><source_ip>2.2.2.2</source_ip><policy_evaluated><dkim>pass</dkim></policy_evaluated></row></record>" +
            "</feedback>";
        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".zip");
        using (var archive = ZipFile.Open(tmp, ZipArchiveMode.Create)) {
            var entry = archive.CreateEntry("report.xml");
            using var stream = entry.Open();
            using var writer = new StreamWriter(stream, Encoding.UTF8);
            writer.Write(xml);
        }
        var report = DmarcReportParser.Parse(tmp);
        File.Delete(tmp);
        Assert.Equal(2, report.RecordCount);
    }
}
