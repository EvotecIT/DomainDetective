using System;
using System.Collections.Generic;
using System.IO;
using DnsClientX;
using DomainDetective.Providers.Dns;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Providers.Email;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestHtmlDashboardDiscoverySmoke
{
    [Fact]
    public void Html_Renders_Discovery_Checks_With_Evidence()
    {
        var items = new List<object>();
        var domain = "example.org";

        items.Add(new DomainDetective.Views.MxInfo { Subject = domain, Status = "OK" });
        items.Add(new DomainDetective.Views.SubdomainsInfo { Subject = domain, SubdomainCount = 12 });
        items.Add(new DomainDetective.Views.CtTimelineInfo { Subject = domain, UniqueCertificateCount = 3, IssuedLast7Days = 1, IssuedLast30Days = 2 });
        items.Add(new DomainDetective.Views.DnsInventoryInfo { Subject = domain, Provider = DnsProvider.Cloudflare, MailProvider = MailProviderKind.Microsoft365 });
        items.Add(new DomainDetective.Views.Microsoft365TenantInfo
        {
            Subject = domain,
            Status = "Warning",
            IsMicrosoft365Tenant = true,
            DetectionConfidence = DomainDetective.Microsoft365DetectionConfidence.Strong,
            TenantDomains = new[]
            {
                new DomainDetective.Microsoft365TenantDomain
                {
                    Domain = domain,
                    Role = DomainDetective.Microsoft365TenantDomainRole.Primary,
                    Confidence = DomainDetective.Microsoft365DetectionConfidence.Strong
                },
                new DomainDetective.Microsoft365TenantDomain
                {
                    Domain = "groups.example.org",
                    Role = DomainDetective.Microsoft365TenantDomainRole.AcceptedCustomDomain,
                    Confidence = DomainDetective.Microsoft365DetectionConfidence.Moderate
                },
                new DomainDetective.Microsoft365TenantDomain
                {
                    Domain = "exampletenant.onmicrosoft.com",
                    Role = DomainDetective.Microsoft365TenantDomainRole.MicrosoftManagedNamespace,
                    Confidence = DomainDetective.Microsoft365DetectionConfidence.Strong
                }
            },
            Services = new[]
            {
                new DomainDetective.Microsoft365ServiceDetection
                {
                    Kind = DomainDetective.Microsoft365ServiceKind.ExchangeOnline,
                    Status = DomainDetective.Microsoft365DetectionStatus.Detected,
                    Confidence = DomainDetective.Microsoft365DetectionConfidence.Strong,
                    EvidenceSource = DomainDetective.Microsoft365ServiceEvidenceSourceKind.MailProtocol
                },
                new DomainDetective.Microsoft365ServiceDetection
                {
                    Kind = DomainDetective.Microsoft365ServiceKind.Teams,
                    Status = DomainDetective.Microsoft365DetectionStatus.Detected,
                    Confidence = DomainDetective.Microsoft365DetectionConfidence.Moderate,
                    EvidenceSource = DomainDetective.Microsoft365ServiceEvidenceSourceKind.KnownSubdomain,
                    TenantContextBoosted = true
                }
            }
        });
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
            Results = new List<DomainDetective.Views.DnsPropagationResultInfo>
            {
                new()
                {
                    ServerAddress = "1.1.1.1",
                    Country = "United States",
                    RecordType = DnsRecordType.A,
                    Records = new[] { "1.1.1.1" },
                    Duration = TimeSpan.FromMilliseconds(12),
                    Success = true
                },
                new()
                {
                    ServerAddress = "2.2.2.2",
                    Country = "Poland",
                    RecordType = DnsRecordType.A,
                    Records = new[] { "2.2.2.2" },
                    Duration = TimeSpan.FromMilliseconds(25),
                    Success = true
                },
                new()
                {
                    ServerAddress = "3.3.3.3",
                    Country = "United States",
                    RecordType = DnsRecordType.A,
                    Records = Array.Empty<string>(),
                    Duration = TimeSpan.FromMilliseconds(40),
                    Success = false,
                    Error = "Timeout"
                }
            }
        });

        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        HtmlCompositionReport.Generate(tmp, items, ReportScope.Minimal);
        var html = File.ReadAllText(tmp);

        // Every discovery input appears as a check in the assessment report, with its evidence.
        foreach (string section in new[] { "DNS propagation", "Subdomains", "DNS inventory", "Microsoft 365", "HTTP", "IP enrichment" })
        {
            Assert.Contains(section, html, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Contains("Poland", html, StringComparison.Ordinal);
        Assert.Contains("Timeout", html, StringComparison.Ordinal);    }
}
