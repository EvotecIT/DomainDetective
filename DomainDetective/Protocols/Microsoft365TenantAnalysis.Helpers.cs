using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Helpers;
using DomainDetective.Providers.Dns;
using DomainDetective.Providers.Email;

namespace DomainDetective;

public sealed partial class Microsoft365TenantAnalysis {
    private static IReadOnlyList<KnownMicrosoft365Subdomain> BuildKnownSubdomains(SubdomainsAnalysis? subdomains, string domain) {
        if (subdomains?.Subdomains == null || subdomains.Subdomains.Count == 0) {
            return Array.Empty<KnownMicrosoft365Subdomain>();
        }

        var list = new List<KnownMicrosoft365Subdomain>();
        foreach (var entry in subdomains.Subdomains) {
            if (entry == null || string.IsNullOrWhiteSpace(entry.Name)) {
                continue;
            }

            var role = ClassifySubdomainRole(entry.Name, domain);
            if (role == KnownSubdomainRole.Unknown) {
                continue;
            }

            list.Add(new KnownMicrosoft365Subdomain {
                Name = entry.Name,
                Role = role,
                ResolutionStatus = entry.ResolutionStatus,
                Evidence = BuildSubdomainEvidence(entry, role)
            });
        }

        return list
            .OrderBy(static item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IReadOnlyList<string> BuildSubdomainEvidence(SubdomainDiscoveryEntry entry, KnownSubdomainRole role) {
        var evidence = new List<string> {
            $"Role: {role}"
        };
        if (entry.ResolutionStatus != SubdomainResolutionStatus.Unknown) {
            evidence.Add($"Resolution: {entry.ResolutionStatus}");
        }
        if (entry.CtSources != null && entry.CtSources.Count > 0) {
            evidence.Add($"CT: {string.Join(", ", entry.CtSources.Take(3))}");
        }
        return evidence;
    }

    private static IReadOnlyList<DetectedDnsApplication> BuildDetectedApplications(
        DnsInventoryAnalysis? dnsInventory,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var apps = new List<DetectedDnsApplication>();
        if (dnsInventory?.DetectedDnsApplications?.Count > 0) {
            apps.AddRange(dnsInventory.DetectedDnsApplications);
        }
        if (dnsInventory != null) {
            apps.AddRange(DetectedDnsApplicationCatalog.DetectFromInventory(dnsInventory));
        }

        foreach (var mappedApplication in knownSubdomains
                     .Select(static knownSubdomain => TryBuildSubdomainRoleApplication(knownSubdomain))
                     .Where(static mappedApplication => mappedApplication.HasValue)
                     .Select(static mappedApplication => mappedApplication!.Value)) {
            AddApp(
                apps,
                mappedApplication.Id,
                mappedApplication.Name,
                mappedApplication.Category,
                DetectedDnsAppEvidenceKind.Subdomain,
                mappedApplication.Confidence,
                mappedApplication.KnownSubdomain.Name,
                mappedApplication.KnownSubdomain.Role.ToString());
        }

        return apps
            .GroupBy(static app => $"{app.Id}|{app.EvidenceKind}|{app.Evidence}", StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderBy(static app => app.Category)
            .ThenBy(static app => app.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static (KnownMicrosoft365Subdomain KnownSubdomain, string Id, string Name, DetectedDnsAppCategory Category, Microsoft365DetectionConfidence Confidence)? TryBuildSubdomainRoleApplication(KnownMicrosoft365Subdomain knownSubdomain) {
        if (!TryMapSubdomainRoleApplication(knownSubdomain.Role, out var id, out var name, out var category)) {
            return null;
        }

        return (
            knownSubdomain,
            id,
            name,
            category,
            MapSubdomainRoleApplicationConfidence(knownSubdomain.Role));
    }

    private static void AddApp(
        List<DetectedDnsApplication> apps,
        string id,
        string name,
        DetectedDnsAppCategory category,
        DetectedDnsAppEvidenceKind evidenceKind,
        Microsoft365DetectionConfidence confidence,
        string evidence,
        string? source) {
        apps.Add(new DetectedDnsApplication {
            Id = id,
            Name = name,
            Category = category,
            EvidenceKind = evidenceKind,
            Confidence = confidence,
            Evidence = evidence,
            Source = source
        });
    }

    private static IReadOnlyList<Microsoft365ServiceDetection> BuildServiceDetections(
        IdpInfoAnalysis? idp,
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        return new List<Microsoft365ServiceDetection> {
            BuildExchangeDetection(dnsInventory, autodiscover, knownSubdomains),
            BuildRoleBasedDetection(Microsoft365ServiceKind.SharePointOnline, KnownSubdomainRole.SharePoint, knownSubdomains),
            BuildRoleBasedDetection(Microsoft365ServiceKind.OneDrive, KnownSubdomainRole.OneDrive, knownSubdomains),
            BuildTeamsDetection(knownSubdomains),
            BuildIntuneDetection(knownSubdomains),
            BuildUnknownDetection(Microsoft365ServiceKind.Defender),
            BuildEntraDetection(idp, knownSubdomains),
            BuildPowerAppsDetection(knownSubdomains),
            BuildPowerAutomateDetection(knownSubdomains),
            BuildPowerBiDetection(knownSubdomains)
        };
    }

    private static Microsoft365WorkloadConfidenceSummary BuildWorkloadSummary(IReadOnlyList<Microsoft365ServiceDetection> services) {
        var detected = services
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .ToList();

        return new Microsoft365WorkloadConfidenceSummary {
            DetectedCount = detected.Count,
            StrongCount = detected.Count(static service => service.Confidence == Microsoft365DetectionConfidence.Strong),
            ModerateCount = detected.Count(static service => service.Confidence == Microsoft365DetectionConfidence.Moderate),
            WeakCount = detected.Count(static service => service.Confidence == Microsoft365DetectionConfidence.Weak),
            StrongServices = detected
                .Where(static service => service.Confidence == Microsoft365DetectionConfidence.Strong)
                .Select(static service => service.Kind)
                .ToList(),
            ModerateServices = detected
                .Where(static service => service.Confidence == Microsoft365DetectionConfidence.Moderate)
                .Select(static service => service.Kind)
                .ToList(),
            WeakServices = detected
                .Where(static service => service.Confidence == Microsoft365DetectionConfidence.Weak)
                .Select(static service => service.Kind)
                .ToList()
        };
    }

    private static Microsoft365DnsApplicationSummary BuildDnsApplicationSummary(IReadOnlyList<DetectedDnsApplication> detectedApplications) {
        var categories = detectedApplications
            .Where(static app => app.Category != DetectedDnsAppCategory.Unknown)
            .GroupBy(static app => app.Category)
            .Select(group => new Microsoft365DnsApplicationCategorySummary {
                Category = group.Key,
                Count = group.Count(),
                HighestConfidence = group.Max(static app => app.Confidence),
                ApplicationNames = group
                    .Select(static app => app.Name)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
                    .ToList()
            })
            .OrderByDescending(static item => item.Count)
            .ThenByDescending(static item => item.HighestConfidence)
            .ThenBy(static item => GetDetectedDnsAppCategorySortOrder(item.Category))
            .ThenBy(static item => item.Category.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var dominantCategory = categories.Count > 0 ? categories[0].Category : DetectedDnsAppCategory.Unknown;
        var dominantCategoryCount = categories.Count > 0 ? categories[0].Count : 0;

        return new Microsoft365DnsApplicationSummary {
            TotalCount = detectedApplications.Count,
            CategoryCount = categories.Count,
            DominantCategory = dominantCategory,
            DominantCategoryCount = dominantCategoryCount,
            Categories = categories
        };
    }

    private static int GetDetectedDnsAppCategorySortOrder(DetectedDnsAppCategory category) {
        switch (category) {
            case DetectedDnsAppCategory.Productivity:
                return 0;
            case DetectedDnsAppCategory.Identity:
                return 1;
            case DetectedDnsAppCategory.Security:
                return 2;
            case DetectedDnsAppCategory.Analytics:
                return 3;
            case DetectedDnsAppCategory.EmailSecurity:
                return 4;
            case DetectedDnsAppCategory.EmailMarketing:
                return 5;
            case DetectedDnsAppCategory.EmailSignatures:
                return 6;
            case DetectedDnsAppCategory.DmarcReporting:
                return 7;
            case DetectedDnsAppCategory.DnsHosting:
                return 8;
            case DetectedDnsAppCategory.CDN:
                return 9;
            case DetectedDnsAppCategory.CRM:
                return 10;
            case DetectedDnsAppCategory.Verification:
                return 11;
            case DetectedDnsAppCategory.Other:
                return 12;
            case DetectedDnsAppCategory.Unknown:
            default:
                return int.MaxValue;
        }
    }

    private static Microsoft365ServiceDetection BuildExchangeDetection(
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = new List<string>();
        var autodiscoverTarget = autodiscover?.AutodiscoverTarget;
        var srvTarget = autodiscover?.SrvTarget;
        if (dnsInventory?.MailProvider == MailProviderKind.Microsoft365) {
            evidence.AddRange(dnsInventory.MailProviderEvidence.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(3));
        }
        if (!string.IsNullOrWhiteSpace(autodiscoverTarget) && IsMicrosoftHost(autodiscoverTarget)) {
            evidence.Add("Autodiscover target: " + autodiscoverTarget);
        }
        if (!string.IsNullOrWhiteSpace(srvTarget) && IsMicrosoftHost(srvTarget)) {
            evidence.Add("Autodiscover SRV: " + srvTarget);
        }
        evidence.AddRange(
            knownSubdomains
                .Where(item =>
                    item.Role == KnownSubdomainRole.Autodiscover ||
                    item.Role == KnownSubdomainRole.Mail ||
                    item.Role == KnownSubdomainRole.Webmail ||
                    item.Role == KnownSubdomainRole.Owa)
                .Select(item => item.Name + " (" + item.Role + ")")
                .Take(4));

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.ExchangeOnline,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = BuildExchangeConfidence(dnsInventory, autodiscover, knownSubdomains),
                Evidence = evidence
            };
        }

        if (dnsInventory != null && dnsInventory.QuerySucceeded && dnsInventory.MailProvider != MailProviderKind.Unknown && dnsInventory.MailProvider != MailProviderKind.Microsoft365) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.ExchangeOnline,
                Status = Microsoft365DetectionStatus.NotDetected,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = dnsInventory.MailProviderEvidence ?? Array.Empty<string>()
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.ExchangeOnline);
    }

    private static Microsoft365ServiceDetection BuildTeamsDetection(IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == KnownSubdomainRole.Teams || item.Role == KnownSubdomainRole.LyncDiscover || item.Role == KnownSubdomainRole.Sip)
            .Select(item => $"{item.Name} ({item.Role})")
            .ToList();

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.Teams,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.Teams);
    }

    private static Microsoft365ServiceDetection BuildIntuneDetection(IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == KnownSubdomainRole.EnterpriseEnrollment || item.Role == KnownSubdomainRole.EnterpriseRegistration)
            .Select(item => $"{item.Name} ({item.Role})")
            .ToList();

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.IntuneEndpoint,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.IntuneEndpoint);
    }

    private static Microsoft365ServiceDetection BuildPowerAppsDetection(IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == KnownSubdomainRole.Apps || item.Role == KnownSubdomainRole.Portal)
            .Select(item => $"{item.Name} ({item.Role})")
            .ToList();

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.PowerApps,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = evidence.Any(static item => item.IndexOf("(Apps)", StringComparison.OrdinalIgnoreCase) >= 0)
                    ? Microsoft365DetectionConfidence.Moderate
                    : Microsoft365DetectionConfidence.Weak,
                Evidence = evidence
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.PowerApps);
    }

    private static Microsoft365ServiceDetection BuildPowerAutomateDetection(IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == KnownSubdomainRole.Flow || item.Role == KnownSubdomainRole.Automate)
            .Select(item => $"{item.Name} ({item.Role})")
            .ToList();

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.PowerAutomate,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.PowerAutomate);
    }

    private static Microsoft365ServiceDetection BuildPowerBiDetection(IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == KnownSubdomainRole.PowerBi)
            .Select(item => $"{item.Name} ({item.Role})")
            .ToList();

        if (evidence.Count > 0) {
            return new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.PowerBi,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            };
        }

        return BuildUnknownDetection(Microsoft365ServiceKind.PowerBi);
    }

    private static Microsoft365ServiceDetection BuildRoleBasedDetection(
        Microsoft365ServiceKind kind,
        KnownSubdomainRole expectedRole,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = knownSubdomains
            .Where(item => item.Role == expectedRole)
            .Select(item => item.Name)
            .ToList();

        return evidence.Count > 0
            ? new Microsoft365ServiceDetection {
                Kind = kind,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            }
            : BuildUnknownDetection(kind);
    }

    private static Microsoft365ServiceDetection BuildEntraDetection(
        IdpInfoAnalysis? idp,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var evidence = new List<string>();
        if (idp?.DiscoverySucceeded == true && !string.IsNullOrWhiteSpace(idp.DiscoveryUrl)) {
            evidence.Add(idp.DiscoveryUrl!);
        }
        if (idp?.GetUserRealmSucceeded == true && !string.IsNullOrWhiteSpace(idp.NameSpaceType)) {
            evidence.Add("GetUserRealm: " + idp.NameSpaceType);
        }
        evidence.AddRange(
            knownSubdomains
                .Where(item =>
                    item.Role == KnownSubdomainRole.FederationService ||
                    item.Role == KnownSubdomainRole.Login ||
                    item.Role == KnownSubdomainRole.MsoId ||
                    item.Role == KnownSubdomainRole.EnterpriseEnrollment ||
                    item.Role == KnownSubdomainRole.EnterpriseRegistration)
                .Select(item => item.Name + " (" + item.Role + ")")
                .Take(5));

        return evidence.Count > 0
            ? new Microsoft365ServiceDetection {
                Kind = Microsoft365ServiceKind.EntraId,
                Status = Microsoft365DetectionStatus.Detected,
                Confidence = (idp?.DiscoverySucceeded == true || idp?.GetUserRealmSucceeded == true)
                    ? Microsoft365DetectionConfidence.Strong
                    : Microsoft365DetectionConfidence.Moderate,
                Evidence = evidence
            }
            : BuildUnknownDetection(Microsoft365ServiceKind.EntraId);
    }

    private static Microsoft365ServiceDetection BuildUnknownDetection(Microsoft365ServiceKind kind) {
        return new Microsoft365ServiceDetection {
            Kind = kind,
            Status = Microsoft365DetectionStatus.Unknown,
            Confidence = Microsoft365DetectionConfidence.Unknown,
            Evidence = Array.Empty<string>()
        };
    }

    private static Microsoft365DetectionConfidence BuildExchangeConfidence(
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains) {
        var autodiscoverTarget = autodiscover?.AutodiscoverTarget;
        var srvTarget = autodiscover?.SrvTarget;

        if (dnsInventory?.MailProvider == MailProviderKind.Microsoft365) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (!string.IsNullOrWhiteSpace(autodiscoverTarget) && IsMicrosoftHost(autodiscoverTarget)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (!string.IsNullOrWhiteSpace(srvTarget) && IsMicrosoftHost(srvTarget)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        return knownSubdomains.Any(item =>
                item.Role == KnownSubdomainRole.Autodiscover ||
                item.Role == KnownSubdomainRole.Mail ||
                item.Role == KnownSubdomainRole.Webmail ||
                item.Role == KnownSubdomainRole.Owa)
            ? Microsoft365DetectionConfidence.Moderate
            : Microsoft365DetectionConfidence.Unknown;
    }

    private static Microsoft365DetectionConfidence MapSubdomainRoleApplicationConfidence(KnownSubdomainRole role) {
        switch (role) {
            case KnownSubdomainRole.FederationService:
            case KnownSubdomainRole.Login:
            case KnownSubdomainRole.MsoId:
            case KnownSubdomainRole.EnterpriseEnrollment:
            case KnownSubdomainRole.EnterpriseRegistration:
                return Microsoft365DetectionConfidence.Moderate;
            case KnownSubdomainRole.Autodiscover:
            case KnownSubdomainRole.Mail:
            case KnownSubdomainRole.Webmail:
            case KnownSubdomainRole.Owa:
            case KnownSubdomainRole.SharePoint:
            case KnownSubdomainRole.OneDrive:
            case KnownSubdomainRole.Teams:
            case KnownSubdomainRole.LyncDiscover:
            case KnownSubdomainRole.Sip:
            case KnownSubdomainRole.Apps:
            case KnownSubdomainRole.Flow:
            case KnownSubdomainRole.Automate:
            case KnownSubdomainRole.PowerBi:
                return Microsoft365DetectionConfidence.Moderate;
            case KnownSubdomainRole.Portal:
            case KnownSubdomainRole.Cdn:
            case KnownSubdomainRole.StaticAssets:
            case KnownSubdomainRole.Api:
            case KnownSubdomainRole.Gateway:
            case KnownSubdomainRole.Vpn:
                return Microsoft365DetectionConfidence.Weak;
            default:
                return Microsoft365DetectionConfidence.Unknown;
        }
    }

    private static bool DetermineMicrosoft365Presence(
        IdpInfoAnalysis? idp,
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains,
        IReadOnlyList<DetectedDnsApplication> apps,
        IReadOnlyList<Microsoft365ServiceDetection> services) {
        var autodiscoverTarget = autodiscover?.AutodiscoverTarget;
        if (idp?.DiscoverySucceeded == true || idp?.GetUserRealmSucceeded == true) return true;
        if (dnsInventory?.MailProvider == MailProviderKind.Microsoft365) return true;
        if (dnsInventory != null && dnsInventory.TxtSignals.HasFlag(DnsTxtSignals.MicrosoftDomainVerification)) return true;
        if (!string.IsNullOrWhiteSpace(autodiscoverTarget) && IsMicrosoftHost(autodiscoverTarget)) return true;
        if (knownSubdomains.Any(static item =>
            item.Role == KnownSubdomainRole.EnterpriseEnrollment ||
            item.Role == KnownSubdomainRole.EnterpriseRegistration ||
            item.Role == KnownSubdomainRole.MsoId ||
            item.Role == KnownSubdomainRole.SharePoint ||
            item.Role == KnownSubdomainRole.OneDrive ||
            item.Role == KnownSubdomainRole.Teams)) return true;
        if (apps.Any(static app => string.Equals(app.Id, "microsoft-365", StringComparison.OrdinalIgnoreCase))) return true;
        return services.Any(static service => service.Status == Microsoft365DetectionStatus.Detected);
    }

    private static IReadOnlyList<Microsoft365EvidenceItem> BuildEvidenceLedger(
        IdpInfoAnalysis? idp,
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<Microsoft365ServiceDetection> services,
        IReadOnlyList<DetectedDnsApplication> apps,
        IReadOnlyList<Microsoft365TenantDomain> tenantDomains) {
        var items = new List<Microsoft365EvidenceItem>();

        AddIdentityEvidence(items, idp);
        AddMailEvidence(items, dnsInventory, autodiscover);
        AddServiceEvidence(items, services);
        AddDnsApplicationEvidence(items, apps);
        AddTenantDomainEvidence(items, tenantDomains);

        return items
            .GroupBy(static item => item.Id, StringComparer.OrdinalIgnoreCase)
            .Select(static group => group.First())
            .OrderByDescending(static item => item.Confidence)
            .ThenBy(static item => item.Category)
            .ThenBy(static item => item.Label, StringComparer.OrdinalIgnoreCase)
            .Take(EvidenceLedgerMaxItems)
            .ToList();
    }

    private static Microsoft365EvidenceSummary BuildEvidenceSummary(IReadOnlyList<Microsoft365EvidenceItem> evidenceLedger) {
        var categories = evidenceLedger
            .Where(static item => item.Category != Microsoft365EvidenceCategory.Unknown)
            .GroupBy(static item => item.Category)
            .Select(group => new Microsoft365EvidenceCategorySummary {
                Category = group.Key,
                Count = group.Count(),
                HighestConfidence = group.Max(static item => item.Confidence),
                Labels = group
                    .Select(static item => item.Label)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static label => label, StringComparer.OrdinalIgnoreCase)
                    .ToList()
            })
            .OrderByDescending(static item => item.Count)
            .ThenByDescending(static item => item.HighestConfidence)
            .ThenBy(static item => GetEvidenceCategorySortOrder(item.Category))
            .ThenBy(static item => item.Category.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var dominantCategory = categories.Count > 0 ? categories[0].Category : Microsoft365EvidenceCategory.Unknown;
        var dominantCategoryCount = categories.Count > 0 ? categories[0].Count : 0;

        return new Microsoft365EvidenceSummary {
            TotalCount = evidenceLedger.Count,
            CategoryCount = categories.Count,
            DominantCategory = dominantCategory,
            DominantCategoryCount = dominantCategoryCount,
            Categories = categories
        };
    }

    private static int GetEvidenceCategorySortOrder(Microsoft365EvidenceCategory category) {
        switch (category) {
            case Microsoft365EvidenceCategory.Identity:
                return 0;
            case Microsoft365EvidenceCategory.Authentication:
                return 1;
            case Microsoft365EvidenceCategory.Service:
                return 2;
            case Microsoft365EvidenceCategory.Mail:
                return 3;
            case Microsoft365EvidenceCategory.DnsApplication:
                return 4;
            case Microsoft365EvidenceCategory.Domain:
                return 5;
            case Microsoft365EvidenceCategory.Unknown:
            default:
                return int.MaxValue;
        }
    }

    private static void AddIdentityEvidence(List<Microsoft365EvidenceItem> items, IdpInfoAnalysis? idp) {
        if (idp?.DiscoverySucceeded == true || idp?.GetUserRealmSucceeded == true) {
            var evidence = new List<string>();
            if (!string.IsNullOrWhiteSpace(idp.DiscoveryUrl)) {
                evidence.Add(idp.DiscoveryUrl!);
            }
            if (!string.IsNullOrWhiteSpace(idp.NameSpaceType)) {
                evidence.Add("Namespace: " + idp.NameSpaceType);
            }
            if (!string.IsNullOrWhiteSpace(idp.IdentityProviderHost)) {
                evidence.Add("Provider: " + idp.IdentityProviderHost);
            }

            items.Add(new Microsoft365EvidenceItem {
                Id = "identity-discovery",
                Label = "Identity discovery",
                Category = Microsoft365EvidenceCategory.Identity,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = evidence
            });
        }
    }

    private static void AddMailEvidence(
        List<Microsoft365EvidenceItem> items,
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover) {
        if (dnsInventory?.MailProvider == MailProviderKind.Microsoft365) {
            items.Add(new Microsoft365EvidenceItem {
                Id = "exchange-mail-provider",
                Label = "Exchange mail routing",
                Category = Microsoft365EvidenceCategory.Mail,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = dnsInventory.MailProviderEvidence ?? Array.Empty<string>()
            });
        }

        var autodiscoverEvidence = new List<string>();
        var autodiscoverTarget = autodiscover?.AutodiscoverTarget;
        var srvTarget = autodiscover?.SrvTarget;
        if (!string.IsNullOrWhiteSpace(autodiscoverTarget) && IsMicrosoftHost(autodiscoverTarget)) {
            autodiscoverEvidence.Add("Autodiscover target: " + autodiscoverTarget);
        }
        if (!string.IsNullOrWhiteSpace(srvTarget) && IsMicrosoftHost(srvTarget)) {
            autodiscoverEvidence.Add("Autodiscover SRV: " + srvTarget);
        }

        if (autodiscoverEvidence.Count > 0) {
            items.Add(new Microsoft365EvidenceItem {
                Id = "exchange-autodiscover",
                Label = "Exchange autodiscover",
                Category = Microsoft365EvidenceCategory.Mail,
                Confidence = Microsoft365DetectionConfidence.Strong,
                Evidence = autodiscoverEvidence
            });
        }
    }

    private static void AddServiceEvidence(List<Microsoft365EvidenceItem> items, IReadOnlyList<Microsoft365ServiceDetection> services) {
        if (services == null || services.Count == 0) {
            return;
        }

        foreach (var service in services) {
            if (service.Status != Microsoft365DetectionStatus.Detected || service.Confidence == Microsoft365DetectionConfidence.Unknown) {
                continue;
            }

            items.Add(new Microsoft365EvidenceItem {
                Id = "service-" + service.Kind.ToString().ToLowerInvariant(),
                Label = "Service: " + service.Kind,
                Category = Microsoft365EvidenceCategory.Service,
                Confidence = service.Confidence,
                Evidence = service.Evidence ?? Array.Empty<string>()
            });
        }
    }

    private static void AddDnsApplicationEvidence(List<Microsoft365EvidenceItem> items, IReadOnlyList<DetectedDnsApplication> apps) {
        if (apps == null || apps.Count == 0) {
            return;
        }

        foreach (var app in apps.OrderByDescending(static app => app.Confidence).ThenBy(static app => app.Name, StringComparer.OrdinalIgnoreCase).Take(8)) {
            if (app.Confidence == Microsoft365DetectionConfidence.Unknown) {
                continue;
            }

            items.Add(new Microsoft365EvidenceItem {
                Id = "app-" + app.Id,
                Label = "DNS app: " + app.Name,
                Category = app.Category == DetectedDnsAppCategory.Identity
                    ? Microsoft365EvidenceCategory.Identity
                    : Microsoft365EvidenceCategory.DnsApplication,
                Confidence = app.Confidence,
                Evidence = new[] { app.Evidence }
            });
        }
    }

    private static void AddTenantDomainEvidence(List<Microsoft365EvidenceItem> items, IReadOnlyList<Microsoft365TenantDomain> tenantDomains) {
        if (tenantDomains == null || tenantDomains.Count == 0) {
            return;
        }

        foreach (var tenantDomain in tenantDomains) {
            if (tenantDomain.Confidence == Microsoft365DetectionConfidence.Unknown) {
                continue;
            }

            var label = tenantDomain.Role == Microsoft365TenantDomainRole.MicrosoftManagedNamespace
                ? "Tenant namespace"
                : "Analyzed domain";

            items.Add(new Microsoft365EvidenceItem {
                Id = "domain-" + tenantDomain.Role.ToString().ToLowerInvariant() + "-" + tenantDomain.Domain,
                Label = label,
                Category = Microsoft365EvidenceCategory.Domain,
                Confidence = tenantDomain.Confidence,
                Evidence = tenantDomain.Evidence ?? Array.Empty<string>()
            });
        }
    }

    private static Microsoft365DetectionConfidence BuildTenantDetectionConfidence(
        IdpInfoAnalysis? idp,
        DnsInventoryAnalysis? dnsInventory,
        AutodiscoverAnalysis? autodiscover,
        IReadOnlyList<KnownMicrosoft365Subdomain> knownSubdomains,
        IReadOnlyList<Microsoft365ServiceDetection> services,
        IReadOnlyList<DetectedDnsApplication> apps) {
        var autodiscoverTarget = autodiscover?.AutodiscoverTarget;

        if (idp?.DiscoverySucceeded == true || idp?.GetUserRealmSucceeded == true) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (dnsInventory?.MailProvider == MailProviderKind.Microsoft365) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (dnsInventory != null && dnsInventory.TxtSignals.HasFlag(DnsTxtSignals.MicrosoftDomainVerification)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (!string.IsNullOrWhiteSpace(autodiscoverTarget) && IsMicrosoftHost(autodiscoverTarget)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (services.Any(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Strong)) {
            return Microsoft365DetectionConfidence.Strong;
        }

        if (services.Any(static service => service.Status == Microsoft365DetectionStatus.Detected && service.Confidence == Microsoft365DetectionConfidence.Moderate) ||
            apps.Any(static app => app.Confidence == Microsoft365DetectionConfidence.Moderate) ||
            knownSubdomains.Count > 0) {
            return Microsoft365DetectionConfidence.Moderate;
        }

        if (apps.Any(static app => app.Confidence == Microsoft365DetectionConfidence.Weak)) {
            return Microsoft365DetectionConfidence.Weak;
        }

        return Microsoft365DetectionConfidence.Unknown;
    }

    private static bool TryMapSubdomainRoleApplication(
        KnownSubdomainRole role,
        out string id,
        out string name,
        out DetectedDnsAppCategory category) {
        switch (role) {
            case KnownSubdomainRole.FederationService:
            case KnownSubdomainRole.Login:
            case KnownSubdomainRole.MsoId:
            case KnownSubdomainRole.EnterpriseEnrollment:
            case KnownSubdomainRole.EnterpriseRegistration:
                id = "microsoft-identity-surface";
                name = "Microsoft Identity Surface";
                category = DetectedDnsAppCategory.Identity;
                return true;
            case KnownSubdomainRole.Autodiscover:
            case KnownSubdomainRole.Mail:
            case KnownSubdomainRole.Webmail:
            case KnownSubdomainRole.Owa:
            case KnownSubdomainRole.SharePoint:
            case KnownSubdomainRole.OneDrive:
            case KnownSubdomainRole.Teams:
            case KnownSubdomainRole.LyncDiscover:
            case KnownSubdomainRole.Sip:
                id = "microsoft-365-surface";
                name = "Microsoft 365 Service Surface";
                category = DetectedDnsAppCategory.Productivity;
                return true;
            case KnownSubdomainRole.Apps:
            case KnownSubdomainRole.Portal:
                id = "microsoft-app-platform-surface";
                name = "Microsoft App Platform Surface";
                category = DetectedDnsAppCategory.Productivity;
                return true;
            case KnownSubdomainRole.Flow:
            case KnownSubdomainRole.Automate:
                id = "microsoft-automation-surface";
                name = "Microsoft Automation Surface";
                category = DetectedDnsAppCategory.Productivity;
                return true;
            case KnownSubdomainRole.PowerBi:
                id = "microsoft-analytics-surface";
                name = "Microsoft Analytics Surface";
                category = DetectedDnsAppCategory.Analytics;
                return true;
            case KnownSubdomainRole.Cdn:
            case KnownSubdomainRole.StaticAssets:
                id = "application-delivery-surface";
                name = "Application Delivery Surface";
                category = DetectedDnsAppCategory.CDN;
                return true;
            case KnownSubdomainRole.Api:
            case KnownSubdomainRole.Gateway:
                id = "application-api-surface";
                name = "Application API Surface";
                category = DetectedDnsAppCategory.Other;
                return true;
            case KnownSubdomainRole.Vpn:
                id = "remote-access-surface";
                name = "Remote Access Surface";
                category = DetectedDnsAppCategory.Security;
                return true;
            default:
                id = string.Empty;
                name = string.Empty;
                category = DetectedDnsAppCategory.Unknown;
                return false;
        }
    }

    private static KnownSubdomainRole ClassifySubdomainRole(string fqdn, string baseDomain) {
        var normalizedName = NormalizeHost(fqdn);
        var normalizedBase = NormalizeHost(baseDomain);
        if (normalizedName.Length == 0 || normalizedBase.Length == 0) return KnownSubdomainRole.Unknown;
        if (normalizedBase.IndexOf('.') < 0) return KnownSubdomainRole.Unknown;
        if (!DomainHelper.IsDomainOrSubdomainOfNormalized(normalizedName, normalizedBase)) return KnownSubdomainRole.Unknown;
        if (string.Equals(normalizedName, normalizedBase, StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Unknown;

        var relative = normalizedName.Substring(0, normalizedName.Length - normalizedBase.Length - 1);
        if (relative.Length == 0) return KnownSubdomainRole.Unknown;

        if (relative.StartsWith("selector1._domainkey", StringComparison.OrdinalIgnoreCase) ||
            relative.StartsWith("selector2._domainkey", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.DkimSelector;

        var labels = relative.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0) return KnownSubdomainRole.Unknown;

        var first = labels[0];
        if (string.Equals(first, "autodiscover", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Autodiscover;
        if (string.Equals(first, "enterpriseregistration", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.EnterpriseRegistration;
        if (string.Equals(first, "enterpriseenrollment", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.EnterpriseEnrollment;
        if (string.Equals(first, "lyncdiscover", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.LyncDiscover;
        if (string.Equals(first, "sip", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Sip;
        if (string.Equals(first, "msoid", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.MsoId;
        if (string.Equals(first, "sharepoint", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.SharePoint;
        if (string.Equals(first, "onedrive", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.OneDrive;
        if (string.Equals(first, "teams", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Teams;
        if (string.Equals(first, "portal", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Portal;
        if (string.Equals(first, "fs", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.FederationService;
        if (string.Equals(first, "login", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Login;
        if (string.Equals(first, "vpn", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Vpn;
        if (string.Equals(first, "mail", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Mail;
        if (string.Equals(first, "webmail", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Webmail;
        if (string.Equals(first, "owa", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Owa;
        if (string.Equals(first, "gateway", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Gateway;
        if (string.Equals(first, "api", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Api;
        if (string.Equals(first, "cdn", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Cdn;
        if (string.Equals(first, "apps", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Apps;
        if (string.Equals(first, "powerbi", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.PowerBi;
        if (string.Equals(first, "flow", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Flow;
        if (string.Equals(first, "automate", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.Automate;
        if (string.Equals(first, "static", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(first, "assets", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(first, "media", StringComparison.OrdinalIgnoreCase)) return KnownSubdomainRole.StaticAssets;

        return KnownSubdomainRole.Unknown;
    }

    private static TenantIdentityProviderKind MapIdentityProviderKind(IdpInfoAnalysis idp) {
        if (!string.IsNullOrWhiteSpace(idp.NameSpaceType) &&
            string.Equals(idp.NameSpaceType, "Federated", StringComparison.OrdinalIgnoreCase)) {
            return TenantIdentityProviderKind.FederatedIdentityProvider;
        }

        if (idp.DiscoverySucceeded || idp.GetUserRealmSucceeded) {
            return TenantIdentityProviderKind.MicrosoftEntraId;
        }

        return TenantIdentityProviderKind.Unknown;
    }

    private static Microsoft365FederationMode MapFederationMode(string? nameSpaceType) {
        if (string.IsNullOrWhiteSpace(nameSpaceType)) return Microsoft365FederationMode.Unknown;
        return nameSpaceType!.Equals("Federated", StringComparison.OrdinalIgnoreCase)
            ? Microsoft365FederationMode.Federated
            : Microsoft365FederationMode.CloudManaged;
    }

    private static TenantCloudInstanceKind MapCloudInstance(string? cloudInstanceName) {
        if (string.IsNullOrWhiteSpace(cloudInstanceName)) return TenantCloudInstanceKind.Unknown;

        var normalized = cloudInstanceName!.Trim().ToLowerInvariant();
        if (normalized.Contains("microsoftonline.com")) return TenantCloudInstanceKind.Global;
        if (normalized.Contains("microsoftonline.us")) return TenantCloudInstanceKind.GCC;
        if (normalized.Contains("usgovcloudapi.net")) return TenantCloudInstanceKind.GCCHigh;
        if (normalized.Contains("appsplatform.us")) return TenantCloudInstanceKind.DoD;
        if (normalized.Contains("partner.microsoftonline.cn") || normalized.Contains("chinacloudapi.cn")) return TenantCloudInstanceKind.China;
        if (normalized.Contains("microsoftonline.de")) return TenantCloudInstanceKind.Germany;
        return TenantCloudInstanceKind.Unknown;
    }

    private static TenantRegionKind MapRegion(string? tenantRegionScope) {
        if (string.IsNullOrWhiteSpace(tenantRegionScope)) return TenantRegionKind.Unknown;

        return tenantRegionScope!.Trim().ToUpperInvariant() switch {
            "NA" => TenantRegionKind.NorthAmerica,
            "EU" => TenantRegionKind.Europe,
            "APAC" => TenantRegionKind.AsiaPacific,
            "WW" => TenantRegionKind.Worldwide,
            _ => TenantRegionKind.Unknown
        };
    }

    private static IReadOnlyList<string> Deduplicate(IReadOnlyList<string>? values) {
        if (values == null || values.Count == 0) return Array.Empty<string>();

        return values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string NormalizeHost(string? value) {
        return (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static bool IsMicrosoftHost(string? host) {
        var normalized = NormalizeHost(host);
        return normalized.EndsWith(".outlook.com", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".outlook.office365.us", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".outlook.office.de", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".outlook.office365.de", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".microsoftonline.com", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".microsoftonline.us", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".partner.microsoftonline.cn", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".office365.com", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".office365.us", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".sharepoint.com", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".sharepoint.us", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".sharepoint.cn", StringComparison.OrdinalIgnoreCase) ||
               normalized.EndsWith(".lync.com", StringComparison.OrdinalIgnoreCase);
    }

}
