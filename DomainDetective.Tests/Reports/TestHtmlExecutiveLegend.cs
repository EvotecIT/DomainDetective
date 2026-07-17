using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Reports.Html;
using Xunit;

namespace DomainDetective.Tests.Reports
{
    public class TestHtmlExecutiveLegend
    {
        [Fact]
        public void Html_Executive_Includes_Status_Legend()
        {
            var items = new List<object>();
            var domain = "example.org";
            items.Add(new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" });
            items.Add(new DomainDetective.Views.SpfRecordInfo { Subject = domain, Status = "Warning", SpfRecordExists = true, StartsCorrectly = true, DnsLookupsCount = 2 });
            items.Add(new DomainDetective.Views.DmarcRecordInfo { Subject = domain, Status = "Error", DmarcRecordExists = false });

            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
            HtmlCompositionReport.Generate(tmp, items, DomainDetective.Reports.ReportScope.Minimal);
            var html = File.ReadAllText(tmp);

            Assert.Contains("Legend", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("OK", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Warning", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Error", html, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Html_Report_Renders_Punycode_Domain_Without_Invalid_Comment_Syntax()
        {
            const string domain = "xn--bcher-kva.de";
            var items = new List<object>
            {
                new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" }
            };
            var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");

            try
            {
                HtmlCompositionReport.Generate(tmp, items, DomainDetective.Reports.ReportScope.Minimal);
                var html = File.ReadAllText(tmp);

                Assert.Contains(domain, html, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("<!-- DD:DOMAIN Mail & DNS -->", html, StringComparison.Ordinal);
                Assert.Contains("data-dd-domain=\"xn--bcher-kva.de\"", html, StringComparison.Ordinal);
            }
            finally
            {
                if (File.Exists(tmp)) File.Delete(tmp);
            }
        }
    }
}

