using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Office;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestDnsPropagationReportSmoke
{
    private static DomainDetective.Views.DnsPropagationInfo BuildView(string domain)
    {
        CountryIdExtensions.TryParse("US", out var us);
        CountryIdExtensions.TryParse("PL", out var pl);

        var results = new List<DnsPropagationResult>
        {
            new DnsPropagationResult
            {
                RecordType = DnsRecordType.A,
                Duration = TimeSpan.FromMilliseconds(18),
                Success = true,
                Records = new[] { "93.184.216.34" },
                Server = new PublicDnsEntry
                {
                    Country = us,
                    IPAddress = IPAddress.Parse("1.1.1.1"),
                    HostName = "one.one.one.one",
                    ASN = "13335",
                    ASNName = "Cloudflare"
                }
            },
            new DnsPropagationResult
            {
                RecordType = DnsRecordType.A,
                Duration = TimeSpan.FromMilliseconds(42),
                Success = true,
                Records = new[] { "93.184.216.35" },
                Server = new PublicDnsEntry
                {
                    Country = pl,
                    IPAddress = IPAddress.Parse("8.8.8.8"),
                    HostName = "dns.google",
                    ASN = "15169",
                    ASNName = "Google"
                }
            },
            new DnsPropagationResult
            {
                RecordType = DnsRecordType.A,
                Duration = TimeSpan.FromMilliseconds(250),
                Success = false,
                Records = Array.Empty<string>(),
                Error = "timeout",
                Server = new PublicDnsEntry
                {
                    Country = us,
                    IPAddress = IPAddress.Parse("9.9.9.9"),
                    HostName = "dns.quad9.net",
                    ASN = "19281",
                    ASNName = "Quad9"
                }
            }
        };

        var report = new DnsPropagationReportAnalysis();
        report.Load(domain, DnsRecordType.A, results);
        return DomainDetective.Views.Converters.Convert(report);
    }

    [Fact]
    public void Html_Document_Renders_DnsPropagation()
    {
        var domain = "example.org";
        var items = new List<object>
        {
            new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" },
            BuildView(domain)
        };

        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        try
        {
            HtmlCompositionReport.Generate(tmp, items, ReportScope.Minimal, profile: HtmlProfile.Document);
            var html = File.ReadAllText(tmp);
            Assert.Contains("DNS Propagation", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("World map", html, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    [Fact]
    public void Excel_Workbook_Generates_With_DnsPropagation()
    {
        var domain = "example.org";
        var items = new List<object>
        {
            new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" },
            BuildView(domain)
        };

        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xlsx");
        try
        {
            ExcelCompositionReport.Generate(tmp, items, ReportScope.Minimal, profile: ExcelProfile.Workbook);
            Assert.True(File.Exists(tmp));
            Assert.True(new FileInfo(tmp).Length > 0);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }
}

