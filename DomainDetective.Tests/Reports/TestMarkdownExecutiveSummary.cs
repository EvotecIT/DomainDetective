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
                MarkdownHtmlReportGenerator.Generate(htmlPath, DomainDetective.Reports.DomainAssessmentBuilder.Build(items));

                var markdownPath = Path.ChangeExtension(htmlPath, ".md");
                Assert.True(File.Exists(htmlPath));
                Assert.True(File.Exists(markdownPath));
                Assert.Contains("<!doctype html>", File.ReadAllText(htmlPath), StringComparison.OrdinalIgnoreCase);
                Assert.Contains("example.org", File.ReadAllText(htmlPath), StringComparison.OrdinalIgnoreCase);
                Assert.Contains("example.org", File.ReadAllText(markdownPath), StringComparison.OrdinalIgnoreCase);
                Assert.Contains("SPF", File.ReadAllText(htmlPath), StringComparison.OrdinalIgnoreCase);
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
