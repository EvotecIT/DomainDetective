using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestPolicyDiscoveryReportParity {
    [Fact]
    public async Task FailedMailPolicyDiscoveryRemainsUnknownInGeneratedReports() {
        var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) =>
            Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });
        await check.VerifySPF("example.com");
        await check.VerifyDMARC("example.com");

        var spf = Converters.Convert(check.SpfAnalysis);
        var dmarc = Converters.Convert(check.DmarcAnalysis);
        Assert.Equal("Unknown", spf.RecordPresence);
        Assert.Equal("Unknown", dmarc.RecordPresence);
        Assert.Equal("Unknown", dmarc.DkimAlignment);
        Assert.Equal("Unknown", dmarc.SpfAlignment);
        Assert.Contains("unknown", spf.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(dmarc.Highlights, highlight => highlight.StartsWith("Published policy:", StringComparison.Ordinal));
        Assert.Contains(("Record Present", "Unknown"), SectionProjectors.BuildSpf(spf)!.Summary);
        Assert.Contains(("Record Present", "Unknown"), SectionProjectors.BuildDmarc(dmarc)!.Summary);
        Assert.Contains(("rua", "Unknown"), SectionProjectors.BuildDmarc(dmarc)!.Summary);

        var directory = Path.Combine(Path.GetTempPath(), "DomainDetective-policy-report-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var items = new object[] { spf, dmarc };
            var htmlPath = Path.Combine(directory, "policies.html");
            var wordPath = Path.Combine(directory, "policies.docx");
            var excelPath = Path.Combine(directory, "policies.xlsx");
            HtmlCompositionReport.Generate(htmlPath, items, ReportScope.Detailed);
            WordCompositionReport.Generate(wordPath, items, ReportScope.Detailed, showInfoFindings: false);
            ExcelCompositionReport.Generate(excelPath, items, ReportScope.Detailed, profile: ExcelProfile.Workbook);

            // The assessment report states the record as unknown, never missing, when the lookup failed.
            string htmlText = NormalizeText(File.ReadAllText(htmlPath));
            Assert.True(Regex.Matches(htmlText, @"Unknown\s+Record").Count >= 2, "The SPF and DMARC checks should each show an unknown record.");
            Assert.DoesNotContain("anyone can send as this domain", htmlText);
            Assert.DoesNotContain("spoofed mail is not rejected", htmlText);
            AssertUnknownPresence(ReadWordText(wordPath));
            var rows = ReadExcelRows(excelPath);
            Assert.True(rows.Count(row => row.Contains("Record Present | Unknown")) >= 2,
                "The SPF and DMARC workbook sections should each show unknown record presence.");
            Assert.DoesNotContain(rows, row => row.Contains("Record Present | No"));
            Assert.Contains(rows, row => row.Contains("RUA Destinations | Unknown"));
            Assert.Contains(rows, row => row.Contains("Alignment | dkim=Unknown / spf=Unknown"));
        } finally {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void DmarcReportCountsBothMailtoAndHttpDestinations() {
        var view = new DmarcRecordInfo {
            DmarcRecordExists = true,
            MailtoRua = new[] { "mailto:agg@example.com" },
            HttpRua = new[] { "https://reports.example.com/agg" },
            HttpRuf = new[] { "https://reports.example.com/forensic" }
        };

        var section = SectionProjectors.BuildDmarc(view)!;
        Assert.Equal(2, section.RuaCount);
        Assert.Equal(1, section.RufCount);
        Assert.Contains(("rua", "2"), section.Summary);
        Assert.Contains(("ruf", "1"), section.Summary);
    }

    private static void AssertUnknownPresence(string text) {
        Assert.True(Regex.Matches(text, @"Record Present\s+Unknown").Count >= 2,
            "The SPF and DMARC sections should each show unknown record presence.");
        Assert.DoesNotMatch(@"Record Present\s+No\b", text);
    }

    private static string NormalizeText(string source) =>
        Regex.Replace(Regex.Replace(source, "<[^>]+>", " "), @"\s+", " ");

    private static string ReadWordText(string path) {
        using var archive = ZipFile.OpenRead(path);
        using var reader = new StreamReader(archive.GetEntry("word/document.xml")!.Open());
        return NormalizeText(reader.ReadToEnd());
    }

    private static List<string> ReadExcelRows(string path) {
        using var archive = ZipFile.OpenRead(path);
        var sharedStrings = new List<string>();
        var sharedEntry = archive.GetEntry("xl/sharedStrings.xml");
        if (sharedEntry != null) {
            using var stream = sharedEntry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            sharedStrings = doc.Descendants(ns + "si")
                .Select(item => string.Concat(item.Descendants(ns + "t").Select(text => text.Value)))
                .ToList();
        }

        var rows = new List<string>();
        foreach (var entry in archive.Entries.Where(item => item.FullName.StartsWith("xl/worksheets/sheet", StringComparison.OrdinalIgnoreCase) && item.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))) {
            using var stream = entry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            foreach (var row in doc.Descendants(ns + "row")) {
                var values = new List<string>();
                foreach (var cell in row.Elements(ns + "c")) {
                    var kind = (string?)cell.Attribute("t");
                    var value = kind == "inlineStr"
                        ? string.Concat(cell.Descendants(ns + "t").Select(text => text.Value))
                        : cell.Element(ns + "v")?.Value;
                    if (kind == "s" && int.TryParse(value, out var index) && index >= 0 && index < sharedStrings.Count)
                        value = sharedStrings[index];
                    if (!string.IsNullOrWhiteSpace(value)) values.Add(value!);
                }
                if (values.Count > 0) rows.Add(string.Join(" | ", values));
            }
        }
        return rows;
    }
}
