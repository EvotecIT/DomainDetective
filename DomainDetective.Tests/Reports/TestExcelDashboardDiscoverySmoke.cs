using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using DnsClientX;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;
using DomainDetective.Reports;
using DomainDetective.Reports.Office;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestExcelDashboardDiscoverySmoke
{
    [Fact]
    public void Excel_Dashboard_Generates()
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

        var tmp = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".xlsx");

        ExcelCompositionReport.Generate(tmp, items, ReportScope.Minimal, profile: ExcelProfile.Dashboard);
        Assert.True(File.Exists(tmp));
        Assert.True(new FileInfo(tmp).Length > 0);

        using var archive = ZipFile.OpenRead(tmp);
        var found = false;
        var foundM365 = false;
        var foundM365WorkloadEvidence = false;
        var foundM365DomainEvidence = false;
        var foundM365AcceptedDomains = false;
        foreach (var entry in archive.Entries)
        {
            if (!entry.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) continue;

            using var stream = entry.Open();
            using var reader = new StreamReader(stream);
            var content = reader.ReadToEnd();
            if (content.Contains("DNS Propagation", StringComparison.OrdinalIgnoreCase))
            {
                found = true;
            }
            if (content.Contains("Microsoft 365 Footprint", StringComparison.OrdinalIgnoreCase) || content.Contains("M365 Domains", StringComparison.OrdinalIgnoreCase))
            {
                foundM365 = true;
            }
            if (content.Contains("M365 Domain Evidence", StringComparison.OrdinalIgnoreCase) || content.Contains("DKIM-derived", StringComparison.OrdinalIgnoreCase))
            {
                foundM365DomainEvidence = true;
            }
            if (content.Contains("M365 Workload Evidence", StringComparison.OrdinalIgnoreCase) || content.Contains("Mail/Protocol", StringComparison.OrdinalIgnoreCase))
            {
                foundM365WorkloadEvidence = true;
            }
            if (content.Contains("M365 Accepted Domains", StringComparison.OrdinalIgnoreCase))
            {
                foundM365AcceptedDomains = true;
            }
            if (found && foundM365 && foundM365WorkloadEvidence && foundM365DomainEvidence && foundM365AcceptedDomains) break;
        }
        Assert.True(found, "Excel dashboard should contain DNS Propagation rollups.");
        Assert.True(foundM365, "Excel dashboard should contain Microsoft 365 rollups.");
        Assert.True(foundM365WorkloadEvidence, "Excel dashboard should contain Microsoft 365 workload evidence rollups.");
        Assert.True(foundM365DomainEvidence, "Excel dashboard should contain Microsoft 365 domain evidence rollups.");
        Assert.True(foundM365AcceptedDomains, "Excel dashboard should contain accepted-domain KPI output.");
    }
}
