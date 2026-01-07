using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DomainDetective;
using DomainDetective.DesiredState;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestDesiredStateParity
{
    [Fact]
    public void DesiredState_Counts_Appear_In_All_Formats()
    {
        var domain = "example.org";
        var desiredWarnings = 2;
        var desiredErrors = 1;
        var bestWarnings = 3;
        var bestErrors = 4;

        var view = new DesiredStateInfo
        {
            Subject = domain,
            Mode = DesiredStateMode.BestPracticesForUnspecified,
            Conforms = false,
            WarningCount = desiredWarnings,
            ErrorCount = desiredErrors,
            BestPracticeWarningCount = bestWarnings,
            BestPracticeErrorCount = bestErrors,
            DesiredAssessments = CreateAssessments(domain, "DesiredState", AssessmentSeverity.Warning, desiredWarnings)
                .Concat(CreateAssessments(domain, "DesiredState", AssessmentSeverity.Error, desiredErrors))
                .ToArray(),
            BestPracticeAssessments = CreateAssessments(domain, "SPF", AssessmentSeverity.Warning, bestWarnings)
                .Concat(CreateAssessments(domain, "SPF", AssessmentSeverity.Error, bestErrors))
                .ToArray(),
            References = new[] { "https://example.org/reference" }
        };

        var items = new List<object> { view };
        var tmpHtml = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        var tmpMd = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");
        var tmpDocx = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".docx");
        var tmpXlsx = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xlsx");

        HtmlCompositionReport.Generate(tmpHtml, items, ReportScope.Detailed);
        MarkdownCompositionReport.Generate(tmpMd, items, ReportScope.Detailed);
        WordCompositionReport.Generate(tmpDocx, items, ReportScope.Detailed, showInfoFindings: false);
        ExcelCompositionReport.Generate(tmpXlsx, items, ReportScope.Detailed, profile: ExcelProfile.Workbook);

        var html = File.ReadAllText(tmpHtml);
        var md = File.ReadAllText(tmpMd);
        var wordXml = ReadZipText(tmpDocx);
        var excelRows = ReadExcelRows(tmpXlsx);

        AssertContainsLabelAndValue(html, "Desired Warnings", desiredWarnings);
        AssertContainsLabelAndValue(html, "Desired Errors", desiredErrors);
        AssertContainsLabelAndValue(html, "Best-Practice Warnings", bestWarnings);
        AssertContainsLabelAndValue(html, "Best-Practice Errors", bestErrors);

        AssertContainsLabelAndValue(md, "Desired State Warnings", desiredWarnings);
        AssertContainsLabelAndValue(md, "Desired State Errors", desiredErrors);
        AssertContainsLabelAndValue(md, "Best-Practice Warnings", bestWarnings);
        AssertContainsLabelAndValue(md, "Best-Practice Errors", bestErrors);

        AssertContainsLabelAndValue(wordXml, "Desired Warnings", desiredWarnings);
        AssertContainsLabelAndValue(wordXml, "Desired Errors", desiredErrors);
        AssertContainsLabelAndValue(wordXml, "Best-Practice Warnings", bestWarnings);
        AssertContainsLabelAndValue(wordXml, "Best-Practice Errors", bestErrors);

        AssertContainsLabelAndValue(excelRows, "Desired Warnings", desiredWarnings);
        AssertContainsLabelAndValue(excelRows, "Desired Errors", desiredErrors);
        AssertContainsLabelAndValue(excelRows, "Best-Practice Warnings", bestWarnings);
        AssertContainsLabelAndValue(excelRows, "Best-Practice Errors", bestErrors);
    }

    private static Assessment[] CreateAssessments(string domain, string category, AssessmentSeverity severity, int count)
    {
        var list = new List<Assessment>();
        for (var i = 0; i < count; i++)
        {
            list.Add(new Assessment
            {
                Severity = severity,
                Category = category,
                Target = domain,
                Code = $"{category}.{severity}.{i + 1}",
                Message = $"Test {category} {severity} #{i + 1}"
            });
        }
        return list.ToArray();
    }

    private static string ReadZipText(string path)
    {
        var sb = new StringBuilder();
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries)
        {
            if (!entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            using var reader = new StreamReader(entry.Open());
            var xml = reader.ReadToEnd();
            var text = Regex.Replace(xml, "<[^>]+>", " ");
            text = Regex.Replace(text, "\\s+", " ").Trim();
            if (text.Length == 0)
            {
                continue;
            }
            sb.Append(' ').Append(text);
        }
        return sb.ToString();
    }

    private static void AssertContainsLabelAndValue(string text, string label, int value)
    {
        Assert.Contains(label, text, StringComparison.OrdinalIgnoreCase);
        var pattern = Regex.Escape(label) + ".{0,200}" + Regex.Escape(value.ToString());
        Assert.Matches(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline), text);
    }

    private static void AssertContainsLabelAndValue(IEnumerable<string> rows, string label, int value)
    {
        var valueText = value.ToString();
        foreach (var row in rows)
        {
            if (row.IndexOf(label, StringComparison.OrdinalIgnoreCase) >= 0 &&
                row.IndexOf(valueText, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return;
            }
        }

        Assert.Fail($"Expected '{label}' with value '{value}' in the same Excel row.");
    }

    private static List<string> ReadExcelRows(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        var sharedStrings = ReadSharedStrings(archive);
        var rows = new List<string>();
        foreach (var entry in archive.Entries)
        {
            if (!entry.FullName.StartsWith("xl/worksheets/sheet", StringComparison.OrdinalIgnoreCase) ||
                !entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            using var stream = entry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            foreach (var row in doc.Descendants(ns + "row"))
            {
                var values = new List<string>();
                foreach (var cell in row.Elements(ns + "c"))
                {
                    var cellText = ExtractCellText(cell, ns, sharedStrings);
                    if (!string.IsNullOrWhiteSpace(cellText))
                    {
                        values.Add(cellText);
                    }
                }

                if (values.Count > 0)
                {
                    rows.Add(string.Join(" | ", values));
                }
            }
        }

        return rows;
    }

    private static List<string> ReadSharedStrings(ZipArchive archive)
    {
        var entry = archive.Entries.FirstOrDefault(e => e.FullName.Equals("xl/sharedStrings.xml", StringComparison.OrdinalIgnoreCase));
        if (entry == null)
        {
            return new List<string>();
        }

        using var stream = entry.Open();
        var doc = XDocument.Load(stream);
        var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
        var strings = new List<string>();
        foreach (var si in doc.Descendants(ns + "si"))
        {
            var text = string.Concat(si.Descendants(ns + "t").Select(t => t.Value));
            strings.Add(text);
        }

        return strings;
    }

    private static string? ExtractCellText(XElement cell, XNamespace ns, List<string> sharedStrings)
    {
        var type = (string?)cell.Attribute("t");
        if (string.Equals(type, "inlineStr", StringComparison.OrdinalIgnoreCase))
        {
            return cell.Element(ns + "is")?.Element(ns + "t")?.Value;
        }

        var value = cell.Element(ns + "v")?.Value;
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (string.Equals(type, "s", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(value, out var index) &&
            index >= 0 &&
            index < sharedStrings.Count)
        {
            return sharedStrings[index];
        }

        return value;
    }
}
