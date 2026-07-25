using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DomainDetective.Reports.Markdown;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestMarkdownExecutiveSummary
    {
        [Fact]
        public void Markdown_ExecutiveSummary_Includes_Dnssec_Rpki()
        {
            var items = new List<object>();
            items.Add(new DomainDetective.Views.MxInfo { Subject = "example.org", Status = "OK" });
            items.Add(new DomainDetective.Views.SpfRecordInfo { Subject = "example.org", Status = "OK" });
            items.Add(new DomainDetective.Views.DmarcRecordInfo { Subject = "example.org", Status = "OK" });
            items.Add(new DomainDetective.Views.DkimRecordInfo { Subject = "example.org", Selector = "s1", Status = "OK", PublicKeyExists = true, KeyLength = 2048, HashAlgorithm = "rsa-sha256" });
            items.Add(new DomainDetective.Views.DnssecStatusInfo { Subject = "example.org", ChainValid = true, DsMatch = true, Status = "OK" });
            items.Add(new DomainDetective.Views.RpkiInfo { Subject = "example.org", TotalChecked = 2, ValidCount = 2, Status = "OK" });

            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");
            MarkdownCompositionReport.Generate(tmp, items, DomainDetective.Reports.ReportScope.Detailed);
            var text = File.ReadAllText(tmp);
            Assert.Contains("DNSSEC", text);
            Assert.Contains("RPKI", text);
            Assert.Contains("chain=valid", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("All valid (2/2)", text, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void MarkdownHtml_Generates_Portable_Html_And_Markdown()
        {
            var items = new List<object>
            {
                new DomainDetective.Views.MxInfo { Subject = "example.org", Status = "OK" },
                new DomainDetective.Views.SpfRecordInfo { Subject = "example.org", Status = "OK" }
            };
            var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            var htmlPath = Path.Combine(directory, "report.html");

            try
            {
                MarkdownCompositionReport.GenerateMarkdownHtml(
                    htmlPath,
                    items,
                    DomainDetective.Reports.ReportScope.Detailed);

                var markdownPath = Path.ChangeExtension(htmlPath, ".md");
                Assert.True(File.Exists(htmlPath));
                Assert.True(File.Exists(markdownPath));
                Assert.Contains("<!doctype html>", File.ReadAllText(htmlPath), StringComparison.OrdinalIgnoreCase);
                Assert.Contains("Executive Summary", File.ReadAllText(markdownPath), StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                if (Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
        }
    }
}

