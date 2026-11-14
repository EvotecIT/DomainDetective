using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DomainDetective;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestMicrosoft365ReportParity
{
    [Fact]
    public void Microsoft365_Section_Appears_In_All_Report_Formats()
    {
        var domain = "contoso.com";
        var tenantId = "11111111-2222-3333-4444-555555555555";

        var view = new Microsoft365TenantInfo
        {
            Subject = domain,
            Status = "Warning",
            WarningCount = 2,
            ErrorCount = 0,
            IsMicrosoft365Tenant = true,
            DetectionConfidence = Microsoft365DetectionConfidence.Strong,
            TenantId = tenantId,
            TenantName = "contosotenant",
            TenantNamespaceDomain = "contosotenant.onmicrosoft.com",
            CompanyName = "Contoso",
            NameSpaceType = "Managed",
            IdentityProviderKind = TenantIdentityProviderKind.MicrosoftEntraId,
            FederationMode = Microsoft365FederationMode.CloudManaged,
            CloudInstance = TenantCloudInstanceKind.Global,
            Region = TenantRegionKind.Europe,
            UserEnumerationStatus = Microsoft365AuthExposureStatus.Exposed,
            SmartLockoutStatus = Microsoft365AuthExposureStatus.Unknown,
            ThrottlingStatus = Microsoft365AuthThrottlingStatus.NoThrottling,
            AuthenticationSummary = new Microsoft365AuthenticationSummary
            {
                ProbeResponsive = true,
                UserEnumerationStatus = Microsoft365AuthExposureStatus.Exposed,
                SmartLockoutStatus = Microsoft365AuthExposureStatus.Unknown,
                ThrottlingStatus = Microsoft365AuthThrottlingStatus.NoThrottling,
                ThrottleStatus = 0,
                AuthenticationPath = Microsoft365AuthPathKind.ManagedRedirect,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = new[] { "IfExistsResult=1" }
            },
            AuthenticationPath = Microsoft365AuthPathKind.ManagedRedirect,
            Highlights = new[] { "Auth path: managed-redirect", "Strong workloads: ExchangeOnline" },
            WorkloadSummary = new Microsoft365WorkloadConfidenceSummary
            {
                StrongCount = 1,
                StrongServices = new[] { Microsoft365ServiceKind.ExchangeOnline }
            },
            Services = new[]
            {
                new Microsoft365ServiceDetection
                {
                    Kind = Microsoft365ServiceKind.ExchangeOnline,
                    Status = Microsoft365DetectionStatus.Detected,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    EvidenceSource = Microsoft365ServiceEvidenceSourceKind.MailProtocol,
                    Evidence = new[] { "MX -> mail.protection.outlook.com" }
                },
                new Microsoft365ServiceDetection
                {
                    Kind = Microsoft365ServiceKind.Defender,
                    Status = Microsoft365DetectionStatus.NotDetected,
                    Confidence = Microsoft365DetectionConfidence.Weak,
                    TenantContextBoosted = true,
                    Evidence = new[] { "No public Microsoft Defender-specific DNS or subdomain signal detected." }
                }
            },
            TenantDomains = new[]
            {
                new Microsoft365TenantDomain
                {
                    Domain = domain,
                    Role = Microsoft365TenantDomainRole.Primary,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = new[] { "Analyzed domain", "GetUserRealm domain: contoso.com" }
                },
                new Microsoft365TenantDomain
                {
                    Domain = "groups.contoso.com",
                    Role = Microsoft365TenantDomainRole.AcceptedCustomDomain,
                    Confidence = Microsoft365DetectionConfidence.Moderate,
                    Evidence = new[] { "DKIM signing domain: selector1._domainkey.groups.contoso.com" }
                },
                new Microsoft365TenantDomain
                {
                    Domain = "contosotenant.onmicrosoft.com",
                    Role = Microsoft365TenantDomainRole.MicrosoftManagedNamespace,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = new[] { "DKIM CNAME: selector1-groups-contoso-com._domainkey.contosotenant.onmicrosoft.com" }
                }
            },
            KnownSubdomains = new[]
            {
                new KnownMicrosoft365Subdomain
                {
                    Name = "login.contoso.com",
                    Role = KnownSubdomainRole.Login,
                    ResolutionStatus = SubdomainResolutionStatus.Resolves
                }
            },
            DetectedDnsApplications = new[]
            {
                new DetectedDnsApplication
                {
                    Id = "microsoft-365",
                    Name = "Microsoft 365",
                    Category = DetectedDnsAppCategory.Productivity,
                    EvidenceKind = DetectedDnsAppEvidenceKind.TxtRecord,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = "MS=ms12345678"
                }
            },
            EvidenceLedger = new[]
            {
                new Microsoft365EvidenceItem
                {
                    Id = "identity-discovery",
                    Label = "Identity discovery",
                    Category = Microsoft365EvidenceCategory.Identity,
                    Confidence = Microsoft365DetectionConfidence.Strong,
                    Evidence = new[] { "OpenID configuration" }
                }
            },
            Assessments = new[]
            {
                new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Category = "Microsoft365",
                    Target = domain,
                    Code = "m365-auth-user-enumeration-exposed",
                    Message = "User enumeration is exposed."
                }
            },
            References = new[] { "https://learn.microsoft.com/en-us/entra/" }
        };

        var report = DomainAssessmentBuilder.Build(new object[] { view });
        var tenant = Assert.Single(Assert.Single(report.Domains).Checks);
        Assert.Contains(tenant.Facts, fact => fact.Label == "Tenant ID" && fact.Value == tenantId);
        Assert.Contains(tenant.Facts, fact => fact.Label == "Company" && fact.Value == "Contoso");
        var directory = Path.Combine(Path.GetTempPath(), "dd-m365-export-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            var paths = new[] { Path.Combine(directory, "report.html"), Path.Combine(directory, "report.md"), Path.Combine(directory, "report.docx"), Path.Combine(directory, "report.xlsx") };
            AssessmentHtmlReport.Generate(paths[0], report);
            AssessmentMarkdownReport.Generate(paths[1], report);
            AssessmentWordReport.Generate(paths[2], report);
            AssessmentExcelReport.Generate(paths[3], report);
            foreach (var path in paths) {
                string text = ReportArtifactText.Read(path);
                Assert.Contains(tenantId, text);
                foreach (string marker in new[] { "groups.contoso.com", "contosotenant.onmicrosoft.com", "Exchange Online", "Defender", "Not Detected", "User enumeration is exposed.", "OpenID configuration" }) {
                    Assert.Contains(marker, text, StringComparison.OrdinalIgnoreCase);
                }
            }
        } finally { Directory.Delete(directory, true); }
    }
}
