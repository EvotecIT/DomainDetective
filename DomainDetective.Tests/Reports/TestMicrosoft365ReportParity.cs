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

        var items = new List<object> { view };
        var tmpHtml = string.Concat(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ".html");
        var tmpMd = string.Concat(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ".md");
        var tmpDocx = string.Concat(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ".docx");
        var tmpXlsx = string.Concat(Path.GetTempPath(), Guid.NewGuid().ToString("N"), ".xlsx");

        HtmlCompositionReport.Generate(tmpHtml, items, ReportScope.Detailed);
        MarkdownCompositionReport.Generate(tmpMd, items, ReportScope.Detailed);
        WordCompositionReport.Generate(tmpDocx, items, ReportScope.Detailed, showInfoFindings: false);
        ExcelCompositionReport.Generate(tmpXlsx, items, ReportScope.Detailed, profile: ExcelProfile.Workbook);

        var html = File.ReadAllText(tmpHtml);
        var markdown = File.ReadAllText(tmpMd);
        var wordXml = ReadZipText(tmpDocx);
        var excelRows = ReadExcelRows(tmpXlsx);

        Assert.Contains("Microsoft 365", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant ID", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Company", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Contoso", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Microsoft 365 Workloads", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Detected Workloads", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Strong", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Observed via", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Mail/Protocol", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Domains", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Domain Evidence", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Primary 1 (Strong), DKIM-derived 1 (Moderate), Namespace-derived 1 (Strong)", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("groups.contoso.com", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Custom Domain", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DKIM signing domain", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant Namespace Domain", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("contosotenant.onmicrosoft.com", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No Throttling", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Global/Commercial", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(tenantId, html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exchange Online", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Defender", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Not Detected", html, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("Microsoft 365", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant ID", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Company", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Contoso", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("M365 Workloads", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Strong 1 [Mail/Protocol 1]", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Domains", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Domain Evidence", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Primary 1 (Strong), DKIM-derived 1 (Moderate), Namespace-derived 1 (Strong)", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("groups.contoso.com", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Custom Domain", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DKIM signing domain", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant Namespace Domain", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("contosotenant.onmicrosoft.com", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No Throttling", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Global/Commercial", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(tenantId, markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exchange Online", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Defender", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Not Detected", markdown, StringComparison.OrdinalIgnoreCase);

        Assert.Contains("Microsoft 365", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant ID", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Company", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Contoso", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Domains", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Domain Evidence", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Primary 1 (Strong), DKIM-derived 1 (Moderate), Namespace-derived 1 (Strong)", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("groups.contoso.com", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Accepted Custom Domain", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("DKIM signing domain", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tenant Namespace Domain", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("contosotenant.onmicrosoft.com", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("No Throttling", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Global/Commercial", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(tenantId, wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Exchange Online", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Defender", wordXml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Not Detected", wordXml, StringComparison.OrdinalIgnoreCase);

        AssertContainsText(excelRows, "Microsoft 365");
        AssertContainsText(excelRows, "Strong 1");
        AssertContainsText(excelRows, "Mail/Protocol");
        AssertContainsLabelAndValue(excelRows, "Tenant ID", tenantId);
        AssertContainsLabelAndValue(excelRows, "Company", "Contoso");
        AssertContainsLabelAndValue(excelRows, "Accepted Domains", "contoso.com, groups.contoso.com");
        AssertContainsLabelAndValue(excelRows, "Domain Evidence", "Primary 1 (Strong), DKIM-derived 1 (Moderate), Namespace-derived 1 (Strong)");
        AssertContainsLabelAndValue(excelRows, "Tenant Namespace Domain", "contosotenant.onmicrosoft.com");
        AssertContainsLabelAndValue(excelRows, "Throttling", "No Throttling");
        AssertContainsLabelAndValue(excelRows, "Cloud Instance", "Global/Commercial");
        AssertContainsText(excelRows, "Exchange Online");
        AssertContainsText(excelRows, "Defender");
        AssertContainsText(excelRows, "Not Detected");
        AssertContainsText(excelRows, "groups.contoso.com");
        AssertContainsText(excelRows, "Accepted Custom Domain");
        AssertContainsText(excelRows, "DKIM signing domain");
    }

    private static string ReadZipText(string path)
    {
        var sb = new StringBuilder();
        using var archive = ZipFile.OpenRead(path);
        foreach (var entry in archive.Entries.Where(static item => item.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
        {
            using var reader = new StreamReader(entry.Open());
            var xml = reader.ReadToEnd();
            var text = Regex.Replace(xml, "<[^>]+>", " ");
            text = Regex.Replace(text, "\\s+", " ").Trim();
            if (text.Length > 0)
            {
                sb.Append(' ').Append(text);
            }
        }

        return sb.ToString();
    }

    private static List<string> ReadExcelRows(string path)
    {
        using var archive = ZipFile.OpenRead(path);
        var sharedStrings = ReadSharedStrings(archive);
        var rows = new List<string>();
        foreach (var entry in archive.Entries.Where(static item =>
                     item.FullName.StartsWith("xl/worksheets/sheet", StringComparison.OrdinalIgnoreCase) &&
                     item.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)))
        {
            using var stream = entry.Open();
            var doc = XDocument.Load(stream);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            foreach (var row in doc.Descendants(ns + "row"))
            {
                var values = new List<string>();
                foreach (var cell in row.Elements(ns + "c"))
                {
                    var text = ExtractCellText(cell, ns, sharedStrings);
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        values.Add(text!);
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
        return doc.Descendants(ns + "si").Select(si => string.Concat(si.Descendants(ns + "t").Select(t => t.Value))).ToList();
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

    private static void AssertContainsLabelAndValue(IEnumerable<string> rows, string label, string value)
    {
        foreach (var row in rows)
        {
            if (row.IndexOf(label, StringComparison.OrdinalIgnoreCase) >= 0 &&
                row.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return;
            }
        }

        Assert.Fail($"Expected '{label}' with value '{value}' in the same Excel row.");
    }

    private static void AssertContainsText(IEnumerable<string> rows, string value)
    {
        if (rows.Any(row => row.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0))
        {
            return;
        }

        Assert.Fail($"Expected '{value}' in Excel rows.");
    }
}
