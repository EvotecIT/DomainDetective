using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using DnsClientX;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestHtmlDashboardDiscoverySmoke
{
    [Fact]
    public void Html_Dashboard_Renders_Discovery_And_Rollups()
    {
        var items = new List<object>();
        var domain = "example.org";

        items.Add(new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" });
        items.Add(new DomainDetective.Views.SubdomainsInfo { Subject = domain, SubdomainCount = 12 });
        items.Add(new DomainDetective.Views.CtTimelineInfo { Subject = domain, UniqueCertificateCount = 3, IssuedLast7Days = 1, IssuedLast30Days = 2 });
        items.Add(new DomainDetective.Views.DnsInventoryInfo { Subject = domain, Provider = DnsProvider.Cloudflare, MailProvider = MailProviderKind.Microsoft365 });
        items.Add(new DomainDetective.Views.IpEnrichmentInfo
        {
            Subject = domain,
            QuerySucceeded = true,
            UniqueIpCount = 2,
            DistinctAsnCount = 1,
            DistinctCountryCount = 1,
            AsnCounts = new Dictionary<int, int> { [64500] = 2 },
            CountryCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { ["US"] = 2 }
        });
        items.Add(new DomainDetective.Views.HttpInfo
        {
            Subject = domain,
            Url = "https://example.org",
            Status = "OK",
            IsReachable = true,
            Grade = GradeLevel.B,
            HstsPresent = true,
            MissingSecurityHeaders = Array.Empty<string>()
        });

        CountryIdExtensions.TryParse("US", out var us);
        CountryIdExtensions.TryParse("PL", out var pl);

        items.Add(new DomainDetective.Views.DnsPropagationInfo
        {
            Subject = domain,
            RecordType = DnsRecordType.A,
            QuerySucceeded = true,
            ServerCount = 3,
            ServerSuccessCount = 2,
            ServerErrorCount = 1,
            DistinctAnswerSets = 2,
            MajorityAnswerSet = "1.1.1.1",
            Results = new List<DnsPropagationResult>
            {
                new()
                {
                    Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("1.1.1.1"), Country = us, Enabled = true },
                    RecordType = DnsRecordType.A,
                    Records = new[] { "1.1.1.1" },
                    Duration = TimeSpan.FromMilliseconds(12),
                    Success = true
                },
                new()
                {
                    Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("2.2.2.2"), Country = pl, Enabled = true },
                    RecordType = DnsRecordType.A,
                    Records = new[] { "2.2.2.2" },
                    Duration = TimeSpan.FromMilliseconds(25),
                    Success = true
                },
                new()
                {
                    Server = new PublicDnsEntry { IPAddress = IPAddress.Parse("3.3.3.3"), Country = us, Enabled = true },
                    RecordType = DnsRecordType.A,
                    Records = Array.Empty<string>(),
                    Duration = TimeSpan.FromMilliseconds(40),
                    Success = false,
                    Error = "Timeout"
                }
            }
        });

        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        HtmlCompositionReport.Generate(tmp, items, ReportScope.Minimal, profile: HtmlProfile.Dashboard);
        var html = File.ReadAllText(tmp);

        Assert.Contains("Discovery", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Inventory", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Dashboard", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Provider Mix", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IP Footprint", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("HTTP Posture", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DNS Propagation", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Propagation by Record Type", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Propagation Hotspots", html, StringComparison.OrdinalIgnoreCase);
    }
}
