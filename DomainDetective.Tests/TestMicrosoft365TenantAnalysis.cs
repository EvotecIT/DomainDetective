using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMicrosoft365TenantAnalysis
{
    [Fact]
    public async Task AggregatesTypedMicrosoft365Signals()
    {
        var idp = new IdpInfoAnalysis();
        SetBackingField(idp, nameof(IdpInfoAnalysis.Domain), "contoso.com");
        SetBackingField(idp, nameof(IdpInfoAnalysis.DiscoverySucceeded), true);
        SetBackingField(idp, nameof(IdpInfoAnalysis.GetUserRealmSucceeded), true);
        SetBackingField(idp, nameof(IdpInfoAnalysis.DiscoveryUrl), "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration");
        SetBackingField(idp, nameof(IdpInfoAnalysis.TenantId), "11111111-2222-3333-4444-555555555555");
        SetBackingField(idp, nameof(IdpInfoAnalysis.NameSpaceType), "Managed");
        SetBackingField(idp, nameof(IdpInfoAnalysis.IdentityProviderHost), "login.microsoftonline.com");
        SetBackingField(idp, nameof(IdpInfoAnalysis.CloudInstanceName), "microsoftonline.com");
        SetBackingField(idp, nameof(IdpInfoAnalysis.TenantRegionScope), "NA");
        SetBackingField(idp, nameof(IdpInfoAnalysis.GrantTypesSupported), new[] { "authorization_code", "implicit" });
        SetBackingField(idp, nameof(IdpInfoAnalysis.ResponseTypesSupported), new[] { "code", "code id_token", "token id_token" });

        var dnsInventory = new DnsInventoryAnalysis {
            QueryOverride = (_, type, _) => {
                var response = new DnsResponse { Status = DnsResponseCode.NoError };
                if (type == DnsRecordType.MX) {
                    response.Answers = new[] {
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.MX, TTL = 300, DataRaw = "10 contoso-com.mail.protection.outlook.com." }
                    };
                } else if (type == DnsRecordType.NS) {
                    response.Answers = new[] {
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.NS, TTL = 300, DataRaw = "gwen.ns.cloudflare.com." }
                    };
                } else if (type == DnsRecordType.SOA) {
                    response.Answers = new[] {
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.SOA, TTL = 3600, DataRaw = "gwen.ns.cloudflare.com hostmaster.contoso.com 1 7200 900 1209600 86400" }
                    };
                } else if (type == DnsRecordType.TXT) {
                    response.Answers = new[] {
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"MS=ms12345678\"" },
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"atlassian-domain-verification=abcd\"" },
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"mailchimp-domain-verification=abcd\"" },
                        new DnsAnswer { Name = "contoso.com", Type = DnsRecordType.TXT, TTL = 60, DataRaw = "\"openai-domain-verification=abcd\"" }
                    };
                }
                return Task.FromResult(response);
            }
        };
        await dnsInventory.AnalyzeAsync("contoso.com", new InternalLogger(), CancellationToken.None);

        var subdomains = new SubdomainsAnalysis();
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subject), "contoso.com");
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.QuerySucceeded), true);
        SetBackingField(
            subdomains,
            nameof(SubdomainsAnalysis.Subdomains),
            new List<SubdomainDiscoveryEntry> {
                new() { Name = "enterpriseenrollment.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "login.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "owa.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "apps.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "flow.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "powerbi.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "sharepoint.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "teams.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "api.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "cdn.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves, CtSources = new[] { "crt.sh" } },
                new() { Name = "selector1._domainkey.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Unknown, CtSources = new[] { "crt.sh" } }
            });

        var autodiscover = new AutodiscoverAnalysis();
        SetBackingField(autodiscover, nameof(AutodiscoverAnalysis.Subject), "contoso.com");
        SetBackingField(autodiscover, nameof(AutodiscoverAnalysis.AutodiscoverCnameExists), true);
        SetBackingField(autodiscover, nameof(AutodiscoverAnalysis.AutodiscoverTarget), "autodiscover.outlook.com");

        var dkim = new DkimAnalysis {
            Subject = "contoso.com"
        };
        dkim.AnalysisResults["selector1"] = new DkimRecordAnalysis {
            Name = "selector1-contoso._domainkey.contosotenant.onmicrosoft.com",
            DkimRecordExists = true,
            StartsCorrectly = true,
            PublicKeyExists = true,
            ValidPublicKey = true
        };

        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", idp, dnsInventory, dkim, subdomains, autodiscover, new InternalLogger());
        await analysis.ProbeAuthenticationAsync("contoso.com", new StubHttpClientFactory(_ => CreateJsonResponse(@"
{
  ""Username"": ""dd-authprobe@contoso.com"",
  ""Display"": ""dd-authprobe@contoso.com"",
  ""IfExistsResult"": 1,
  ""ThrottleStatus"": 1,
  ""Credentials"": { ""PrefCredential"": 4, ""FederationRedirectUrl"": ""https://login.microsoftonline.com/"" },
  ""EstsProperties"": { ""DomainType"": 3 }
}")), new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.IsMicrosoft365Tenant);
        Assert.Equal(Microsoft365DetectionConfidence.Strong, analysis.DetectionConfidence);
        Assert.NotEmpty(analysis.EvidenceLedger);
        Assert.Equal(TenantIdentityProviderKind.MicrosoftEntraId, analysis.IdentityProviderKind);
        Assert.Equal(Microsoft365FederationMode.CloudManaged, analysis.FederationMode);
        Assert.Equal(TenantCloudInstanceKind.Global, analysis.CloudInstance);
        Assert.Equal(TenantRegionKind.NorthAmerica, analysis.Region);
        Assert.Equal("11111111-2222-3333-4444-555555555555", analysis.TenantId);
        Assert.Contains("authorization_code", analysis.SupportedGrantTypes);
        Assert.Contains("code id_token", analysis.SupportedResponseTypes);
        Assert.True(analysis.AuthenticationProbeSucceeded);
        Assert.Equal(Microsoft365AuthExposureStatus.Exposed, analysis.UserEnumerationStatus);
        Assert.Equal(1, analysis.AuthenticationProbe?.IfExistsResult);
        Assert.Equal(3, analysis.AuthenticationProbe?.DomainType);
        Assert.True(analysis.AuthenticationSummary.ProbeResponsive);
        Assert.Equal(Microsoft365DetectionConfidence.Strong, analysis.AuthenticationSummary.Confidence);
        Assert.Equal(Microsoft365AuthExposureStatus.Exposed, analysis.AuthenticationSummary.UserEnumerationStatus);
        Assert.Equal(Microsoft365AuthExposureStatus.Unknown, analysis.AuthenticationSummary.SmartLockoutStatus);
        Assert.Equal(1, analysis.AuthenticationSummary.IfExistsResult);
        Assert.Equal(1, analysis.AuthenticationSummary.ThrottleStatus);
        Assert.Equal(3, analysis.AuthenticationSummary.DomainType);
        Assert.Equal(4, analysis.AuthenticationSummary.PreferredCredential);
        Assert.Equal("https://login.microsoftonline.com/", analysis.AuthenticationSummary.FederationRedirectUrl);
        Assert.Equal(Microsoft365AuthDomainPostureKind.ManagedTenant, analysis.AuthenticationSummary.DomainPosture);
        Assert.Equal(Microsoft365AuthCredentialFlowKind.Redirect, analysis.AuthenticationSummary.CredentialFlow);
        Assert.Equal(Microsoft365AuthPathKind.ManagedRedirect, analysis.AuthenticationSummary.AuthenticationPath);
        Assert.Contains(analysis.AuthenticationSummary.Evidence, item => item == "IfExistsResult=1");
        Assert.Contains(analysis.AuthenticationSummary.Evidence, item => item == "DomainType=3");
        Assert.Contains(analysis.AuthenticationSummary.Evidence, item => item == "PreferredCredential=4");
        Assert.Contains(analysis.TenantDomains, domain => domain.Domain == "contoso.com" && domain.Role == Microsoft365TenantDomainRole.Primary);
        Assert.Contains(analysis.TenantDomains, domain => domain.Domain == "contosotenant.onmicrosoft.com" && domain.Role == Microsoft365TenantDomainRole.MicrosoftManagedNamespace);

        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.ExchangeOnline).Status);
        Assert.Equal(Microsoft365DetectionConfidence.Strong, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.ExchangeOnline).Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.SharePointOnline).Status);
        Assert.Equal(Microsoft365DetectionConfidence.Moderate, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.SharePointOnline).Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.Teams).Status);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.IntuneEndpoint).Status);
        var entraDetection = analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.EntraId);
        Assert.Equal(Microsoft365DetectionStatus.Detected, entraDetection.Status);
        Assert.Equal(Microsoft365DetectionConfidence.Strong, entraDetection.Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.PowerApps).Status);
        Assert.Equal(Microsoft365DetectionConfidence.Moderate, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.PowerApps).Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.PowerAutomate).Status);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.PowerBi).Status);
        Assert.Equal(8, analysis.WorkloadSummary.DetectedCount);
        Assert.Equal(2, analysis.WorkloadSummary.StrongCount);
        Assert.Equal(6, analysis.WorkloadSummary.ModerateCount);
        Assert.Equal(0, analysis.WorkloadSummary.WeakCount);
        Assert.Contains(Microsoft365ServiceKind.ExchangeOnline, analysis.WorkloadSummary.StrongServices);
        Assert.Contains(Microsoft365ServiceKind.EntraId, analysis.WorkloadSummary.StrongServices);
        Assert.Equal(analysis.DetectedDnsApplications.Count, analysis.DnsApplicationSummary.TotalCount);
        Assert.Equal(7, analysis.DnsApplicationSummary.CategoryCount);
        Assert.Equal(DetectedDnsAppCategory.Productivity, analysis.DnsApplicationSummary.DominantCategory);
        Assert.True(analysis.DnsApplicationSummary.DominantCategoryCount >= 5);
        Assert.Equal(analysis.DnsApplicationSummary.DominantCategoryCount, analysis.DnsApplicationSummary.Categories.Single(category => category.Category == DetectedDnsAppCategory.Productivity).Count);
        Assert.Contains("Microsoft 365", analysis.DnsApplicationSummary.Categories.Single(category => category.Category == DetectedDnsAppCategory.Productivity).ApplicationNames);
        Assert.True(analysis.DnsApplicationSummary.Categories.Single(category => category.Category == DetectedDnsAppCategory.Identity).Count >= 1);
        Assert.Equal(analysis.EvidenceLedger.Count, analysis.EvidenceSummary.TotalCount);
        Assert.True(analysis.EvidenceSummary.CategoryCount >= 5);
        Assert.Contains(analysis.EvidenceSummary.Categories, category => category.Category == Microsoft365EvidenceCategory.Identity && category.HighestConfidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.EvidenceSummary.Categories, category => category.Category == Microsoft365EvidenceCategory.Service && category.Count >= 2);
        Assert.Contains(analysis.EvidenceSummary.Categories, category => category.Category == Microsoft365EvidenceCategory.Authentication && category.Count >= 1);

        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.EnterpriseEnrollment);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Login);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Owa);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Apps);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Flow);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.PowerBi);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.SharePoint);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Teams);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Api);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.Cdn);
        Assert.Contains(analysis.KnownSubdomains, item => item.Role == KnownSubdomainRole.DkimSelector);

        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-365");
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-365" && app.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "atlassian");
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "mailchimp" && app.Category == DetectedDnsAppCategory.EmailMarketing && app.Confidence == Microsoft365DetectionConfidence.Weak);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "openai" && app.Category == DetectedDnsAppCategory.Productivity);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Category == DetectedDnsAppCategory.DnsHosting && app.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-identity-surface" && app.Category == DetectedDnsAppCategory.Identity && app.Confidence == Microsoft365DetectionConfidence.Moderate);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-365-surface" && app.Category == DetectedDnsAppCategory.Productivity);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-app-platform-surface" && app.Category == DetectedDnsAppCategory.Productivity);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-automation-surface" && app.Category == DetectedDnsAppCategory.Productivity);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-analytics-surface" && app.Category == DetectedDnsAppCategory.Analytics);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "application-api-surface" && app.Category == DetectedDnsAppCategory.Other && app.Confidence == Microsoft365DetectionConfidence.Weak);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "application-delivery-surface" && app.Category == DetectedDnsAppCategory.CDN && app.Confidence == Microsoft365DetectionConfidence.Weak);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "identity-discovery" && item.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "exchange-mail-provider" && item.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "service-entraid" && item.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "app-microsoft-365" && item.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "domain-microsoftmanagednamespace-contosotenant.onmicrosoft.com" && item.Category == Microsoft365EvidenceCategory.Domain);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "auth-getcredentialtype" && item.Category == Microsoft365EvidenceCategory.Authentication && item.Confidence == Microsoft365DetectionConfidence.Strong);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-probe-detected");
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-user-enumeration-exposed");
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-managed-posture-detected" && assessment.Severity == AssessmentSeverity.Info);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-redirect-flow-detected" && assessment.Severity == AssessmentSeverity.Info);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-managed-redirect-path-detected" && assessment.Severity == AssessmentSeverity.Info);

        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.True(view.AuthenticationSummary.ProbeResponsive);
        Assert.Equal(Microsoft365AuthExposureStatus.Exposed, view.AuthenticationSummary.UserEnumerationStatus);
        Assert.Equal(3, view.AuthenticationSummary.DomainType);
        Assert.Equal(Microsoft365AuthDomainPostureKind.ManagedTenant, view.AuthenticationSummary.DomainPosture);
        Assert.Equal(Microsoft365AuthCredentialFlowKind.Redirect, view.AuthenticationSummary.CredentialFlow);
        Assert.Equal(Microsoft365AuthPathKind.ManagedRedirect, view.AuthenticationPath);
        Assert.Contains("auth-path managed-redirect;", view.Summary);
        Assert.Contains("workloads S2/M6/W0;", view.Summary);
        Assert.Contains("app-cats 7 (top Productivity ", view.Summary);
        Assert.Contains("(strong)", view.Summary);
        Assert.Contains("evidence-groups ", view.Summary);
        Assert.Contains("auth Exposed / Unknown (managed, redirect; DomainType 3; PrefCredential 4)", view.Summary);
        Assert.Equal("Auth path: managed-redirect", view.Highlights.First());
        Assert.Equal("Strong workloads: ExchangeOnline, EntraId", view.Highlights[1]);
        Assert.Contains(view.Highlights, item => item.StartsWith("App footprint: Productivity ", StringComparison.Ordinal) && item.Contains("(strong)", StringComparison.Ordinal));
        Assert.Contains(view.Highlights, item => item.StartsWith("Evidence groups: ", StringComparison.Ordinal) && item.Contains("(strong)", StringComparison.Ordinal) && (item.Contains("Services ", StringComparison.Ordinal) || item.Contains("Apps ", StringComparison.Ordinal) || item.Contains("Identity ", StringComparison.Ordinal)));
        Assert.Contains("User enumeration: exposed", view.Highlights);
        Assert.Contains(view.Recommendations, advice => advice.Code == "m365-auth-user-enumeration-exposed");
        Assert.Contains(view.Positives, advice => advice.Code == "m365-auth-managed-posture-detected");
        Assert.Contains(view.Positives, advice => advice.Code == "m365-auth-redirect-flow-detected");
        Assert.Contains(view.Positives, advice => advice.Code == "m365-auth-managed-redirect-path-detected");
    }

    [Fact]
    public async Task DoesNotFlagUserEnumerationAsExposedWhenProbeIsThrottled() {
        var subdomains = new SubdomainsAnalysis();
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subject), "contoso.com");
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.QuerySucceeded), true);
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subdomains), new List<SubdomainDiscoveryEntry>());

        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", null, null, null, subdomains, null, null);

        await analysis.ProbeAuthenticationAsync("contoso.com", new StubHttpClientFactory(_ => CreateJsonResponse(@"
{
  ""Username"": ""dd-authprobe@contoso.com"",
  ""Display"": ""dd-authprobe@contoso.com"",
  ""IfExistsResult"": 5,
  ""ThrottleStatus"": 1,
  ""Credentials"": { ""PrefCredential"": 4 },
  ""EstsProperties"": { ""DomainType"": 3 }
}")), new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.AuthenticationProbeSucceeded);
        Assert.Equal(Microsoft365AuthExposureStatus.Unknown, analysis.UserEnumerationStatus);
        Assert.DoesNotContain(analysis.Assessments, assessment => assessment.Code == "m365-auth-user-enumeration-exposed");
    }

    [Fact]
    public void IgnoresLookalikeSubdomainsWhenClassifyingKnownRoles() {
        var subdomains = new SubdomainsAnalysis();
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subject), "contoso.com");
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.QuerySucceeded), true);
        SetBackingField(
            subdomains,
            nameof(SubdomainsAnalysis.Subdomains),
            new List<SubdomainDiscoveryEntry> {
                new() { Name = "myteams.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves },
                new() { Name = "filesharepoint.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves },
                new() { Name = "onedrivedocs.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves },
                new() { Name = "powerbireports.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves }
            });

        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", null, null, null, subdomains, null, new InternalLogger());

        Assert.Empty(analysis.KnownSubdomains);
    }

    [Fact]
    public async Task DetectsFederatedRedirectAuthenticationPath()
    {
        var idp = new IdpInfoAnalysis();
        SetBackingField(idp, nameof(IdpInfoAnalysis.Domain), "contoso.com");
        SetBackingField(idp, nameof(IdpInfoAnalysis.DiscoverySucceeded), true);
        SetBackingField(idp, nameof(IdpInfoAnalysis.GetUserRealmSucceeded), true);
        SetBackingField(idp, nameof(IdpInfoAnalysis.NameSpaceType), "Federated");
        SetBackingField(idp, nameof(IdpInfoAnalysis.IdentityProviderHost), "adfs.contoso.com");

        var subdomains = new SubdomainsAnalysis();
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subject), "contoso.com");
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.QuerySucceeded), true);
        SetBackingField(
            subdomains,
            nameof(SubdomainsAnalysis.Subdomains),
            new List<SubdomainDiscoveryEntry> {
                new() { Name = "login.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves }
            });

        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", idp, null, null, subdomains, null, new InternalLogger());
        await analysis.ProbeAuthenticationAsync("contoso.com", new StubHttpClientFactory(_ => CreateJsonResponse(@"
{
  ""Username"": ""dd-authprobe@contoso.com"",
  ""Display"": ""dd-authprobe@contoso.com"",
  ""IfExistsResult"": 1,
  ""ThrottleStatus"": 1,
  ""Credentials"": { ""PrefCredential"": 4, ""FederationRedirectUrl"": ""https://adfs.contoso.com/adfs/ls/"" },
  ""EstsProperties"": { ""DomainType"": 3 }
}")), new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.AuthenticationSummary.ProbeResponsive);
        Assert.Equal(Microsoft365AuthDomainPostureKind.FederatedTenant, analysis.AuthenticationSummary.DomainPosture);
        Assert.Equal(Microsoft365AuthCredentialFlowKind.Redirect, analysis.AuthenticationSummary.CredentialFlow);
        Assert.Equal(Microsoft365AuthPathKind.FederatedRedirect, analysis.AuthenticationSummary.AuthenticationPath);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-federated-posture-detected" && assessment.Severity == AssessmentSeverity.Info);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-redirect-flow-detected" && assessment.Severity == AssessmentSeverity.Info);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-auth-federated-redirect-path-detected" && assessment.Severity == AssessmentSeverity.Info);

        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.Equal(Microsoft365AuthPathKind.FederatedRedirect, view.AuthenticationPath);
        Assert.Contains("auth-path federated-redirect;", view.Summary);
        Assert.Equal("Auth path: federated-redirect", view.Highlights.First());
        Assert.Contains(view.Positives, advice => advice.Code == "m365-auth-federated-posture-detected");
        Assert.Contains(view.Positives, advice => advice.Code == "m365-auth-federated-redirect-path-detected");
    }

    [Fact]
    public void DetectsExchangeAndEntraFromSubdomainRolesWithoutIdentityProbe()
    {
        var subdomains = new SubdomainsAnalysis();
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.Subject), "contoso.com");
        SetBackingField(subdomains, nameof(SubdomainsAnalysis.QuerySucceeded), true);
        SetBackingField(
            subdomains,
            nameof(SubdomainsAnalysis.Subdomains),
            new List<SubdomainDiscoveryEntry> {
                new() { Name = "login.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves },
                new() { Name = "enterpriseenrollment.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves },
                new() { Name = "owa.contoso.com", ResolutionStatus = SubdomainResolutionStatus.Resolves }
            });

        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", null, null, null, subdomains, null, new InternalLogger());

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.IsMicrosoft365Tenant);
        Assert.Equal(Microsoft365DetectionConfidence.Moderate, analysis.DetectionConfidence);
        Assert.NotEmpty(analysis.EvidenceLedger);
        Assert.Equal(3, analysis.WorkloadSummary.DetectedCount);
        Assert.Equal(0, analysis.WorkloadSummary.StrongCount);
        Assert.Equal(3, analysis.WorkloadSummary.ModerateCount);
        Assert.Equal(0, analysis.WorkloadSummary.WeakCount);
        Assert.Equal(analysis.DetectedDnsApplications.Count, analysis.DnsApplicationSummary.TotalCount);
        Assert.Equal(2, analysis.DnsApplicationSummary.CategoryCount);
        Assert.Contains(analysis.DnsApplicationSummary.Categories, category => category.Category == DetectedDnsAppCategory.Productivity);
        Assert.Contains(analysis.DnsApplicationSummary.Categories, category => category.Category == DetectedDnsAppCategory.Identity);
        Assert.True(analysis.DnsApplicationSummary.DominantCategoryCount >= 1);
        Assert.Equal(analysis.EvidenceLedger.Count, analysis.EvidenceSummary.TotalCount);
        Assert.True(analysis.EvidenceSummary.CategoryCount >= 2);
        Assert.Contains(analysis.EvidenceSummary.Categories, category => category.Category == Microsoft365EvidenceCategory.Service && category.Count >= 2);
        Assert.Contains(analysis.TenantDomains, domain => domain.Domain == "contoso.com" && domain.Role == Microsoft365TenantDomainRole.Primary);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.ExchangeOnline).Status);
        Assert.Equal(Microsoft365DetectionConfidence.Moderate, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.ExchangeOnline).Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.EntraId).Status);
        Assert.Equal(Microsoft365DetectionConfidence.Moderate, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.EntraId).Confidence);
        Assert.Equal(Microsoft365DetectionStatus.Detected, analysis.Services.Single(s => s.Kind == Microsoft365ServiceKind.IntuneEndpoint).Status);
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-identity-surface");
        Assert.Contains(analysis.DetectedDnsApplications, app => app.Id == "microsoft-365-surface");
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "service-exchangeonline" && item.Confidence == Microsoft365DetectionConfidence.Moderate);
        Assert.Contains(analysis.EvidenceLedger, item => item.Id == "service-entraid" && item.Confidence == Microsoft365DetectionConfidence.Moderate);

        var view = DomainDetective.Views.Converters.Convert(analysis);
        Assert.Contains("workloads S0/M3/W0;", view.Summary);
        Assert.Contains("app-cats 2 (top ", view.Summary);
        Assert.Contains("evidence-groups ", view.Summary);
        Assert.Equal("Moderate workloads: ExchangeOnline, IntuneEndpoint, EntraId", view.Highlights[0]);
        Assert.Contains(view.Highlights, item => item.StartsWith("App footprint: ", StringComparison.Ordinal) && item.Contains("Productivity 1 (moderate)", StringComparison.Ordinal) && item.Contains("Identity ", StringComparison.Ordinal) && item.Contains("(moderate)", StringComparison.Ordinal));
        Assert.Contains(view.Highlights, item => item.StartsWith("Evidence groups: ", StringComparison.Ordinal) && item.Contains("Services ", StringComparison.Ordinal));
    }

    [Fact]
    public void WarnsWhenNoMatchingSourcesExist()
    {
        var analysis = new Microsoft365TenantAnalysis();
        analysis.Analyze("contoso.com", new IdpInfoAnalysis(), null, null, null, null, null);

        Assert.False(analysis.QuerySucceeded);
        Assert.Equal("No prerequisite Microsoft 365 source analyses were available for this domain.", analysis.FailureReason);
        Assert.False(analysis.AuthenticationSummary.ProbeResponsive);
        Assert.Equal(Microsoft365AuthDomainPostureKind.Unknown, analysis.AuthenticationSummary.DomainPosture);
        Assert.Equal(Microsoft365AuthCredentialFlowKind.Unknown, analysis.AuthenticationSummary.CredentialFlow);
        Assert.Equal(Microsoft365AuthPathKind.Unknown, analysis.AuthenticationSummary.AuthenticationPath);
        Assert.Contains(analysis.Assessments, assessment => assessment.Code == "m365-no-sources");
    }

    private static void SetBackingField(object instance, string propertyName, object? value)
    {
        var field = instance.GetType().GetField($"<{propertyName}>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic);
        field!.SetValue(instance, value);
    }

    private static System.Net.Http.HttpResponseMessage CreateJsonResponse(string json)
    {
        return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.OK) {
            Content = new System.Net.Http.StringContent(json, System.Text.Encoding.UTF8, "application/json")
        };
    }
}
