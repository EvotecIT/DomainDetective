using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class Microsoft365OverviewPresentation
{
    public static IReadOnlyList<DomainOverviewDetailCardView> BuildSnapshotCards(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[]
        {
            BuildTenantDetectionSnapshotCard(info),
            BuildIdentitySnapshotCard(info),
            BuildServiceSnapshotCard(info),
            BuildApplicationSnapshotCard(info),
            BuildAcceptedDomainSnapshotCard(info)
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildIdentityCards(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[]
        {
            BuildTenantIdentityCard(info.Tenant),
            BuildAuthenticationPostureCard(info.Tenant),
            BuildProtocolSurfaceCard(info.Tenant)
        };
    }

    public static IReadOnlyList<string> BuildSnapshotHighlights(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<string>();
        }

        var tenant = info.Tenant;
        var lines = new List<string>();

        if (!string.IsNullOrWhiteSpace(tenant.CompanyName))
        {
            lines.Add("Company: " + tenant.CompanyName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.IdentityProvider))
        {
            lines.Add("Identity provider: " + tenant.IdentityProvider);
        }
        else if (tenant.IdentityProviderKind != TenantIdentityProviderKind.Unknown)
        {
            lines.Add("Identity provider: " + Humanize(tenant.IdentityProviderKind.ToString()));
        }

        var failingChecks = info.MailDnsChecks
            .Where(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning)
            .Take(3)
            .Select(static check => check.Label + ": " + check.Value + " (" + check.Detail + ")");
        lines.AddRange(failingChecks);

        if (lines.Count < 5)
        {
            lines.AddRange(tenant.Services
                .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
                .OrderByDescending(static service => (int)service.Confidence)
                .Take(5 - lines.Count)
                .Select(static service => Humanize(service.Kind.ToString()) + ": " + Humanize(service.EvidenceSource.ToString())));
        }

        if (lines.Count < 5)
        {
            lines.AddRange(tenant.TenantDomains
                .OrderBy(static item => item.Role)
                .Take(5 - lines.Count)
                .Select(static item => item.Domain + " (" + Humanize(item.Role.ToString()) + ")"));
        }

        return lines
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildTenantDetectionSnapshotCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenant.CompanyName))
        {
            samples.Add("Company: " + tenant.CompanyName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantName))
        {
            samples.Add("Tenant name: " + tenant.TenantName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantId))
        {
            samples.Add("Tenant ID: " + tenant.TenantId);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Tenant detection",
            ValueLabel = FormatTenantDetectionLabel(info),
            Summary = info.IsBrowserLimited
                ? "DD used the browser-safe DNS, mail, and application evidence available here. Tenant identity and auth probes require the deeper online run."
                : "DD combined namespace, tenant, and Microsoft identity evidence to decide whether this domain maps to a Microsoft 365 tenant.",
            Tags = new[]
            {
                "Confidence: " + FormatConfidence(tenant.DetectionConfidence),
                "Cloud: " + Humanize(tenant.CloudInstance.ToString()),
                info.IsBrowserLimited ? "Identity probes: unavailable" : "Region: " + Humanize(tenant.Region.ToString())
            },
            Samples = samples.Take(3).ToArray()
        };
    }

    private static string FormatTenantDetectionLabel(Microsoft365OverviewInfo info)
    {
        if (info.IsBrowserLimited)
        {
            return info.Tenant.IsMicrosoft365Tenant ? "Microsoft evidence observed" : "Not confirmed";
        }

        return info.Tenant.IsMicrosoft365Tenant ? "Detected" : "Not detected";
    }

    private static DomainOverviewDetailCardView BuildIdentitySnapshotCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var samples = new List<string>();
        samples.Add("Auth path: " + Humanize(tenant.AuthenticationPath.ToString()));

        if (!string.IsNullOrWhiteSpace(tenant.IdentityProvider))
        {
            samples.Add("Identity provider: " + tenant.IdentityProvider);
        }

        if (tenant.SupportedGrantTypes.Count > 0)
        {
            samples.Add("Grant types: " + string.Join(", ", tenant.SupportedGrantTypes.Take(4)));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Identity posture",
            ValueLabel = FormatIdentityPostureLabel(info),
            Summary = info.IsBrowserLimited
                ? "Microsoft authentication probes do not run in the browser edition, so DD keeps identity posture separate from DNS and mail evidence."
                : "Authentication flow, identity provider, and exposed Microsoft protocol hints shape the public identity posture DD reports here.",
            Tags = new[]
            {
                info.IsBrowserLimited ? "Auth path: unavailable in web edition" : tenant.FederationMode == Microsoft365FederationMode.CloudManaged ? "Cloud-managed" : Humanize(tenant.FederationMode.ToString()),
                info.IsBrowserLimited ? "Provider: deeper online run" : tenant.UserEnumerationStatus == Microsoft365AuthExposureStatus.Exposed ? "User enumeration exposed" : Humanize(tenant.UserEnumerationStatus.ToString()),
                info.IsBrowserLimited ? "Throttling: not probed" : tenant.ThrottlingStatus == Microsoft365AuthThrottlingStatus.ThrottlingObserved ? "Throttling detected" : Humanize(tenant.ThrottlingStatus.ToString())
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildServiceSnapshotCard(Microsoft365OverviewInfo info)
    {
        var samples = info.Tenant.Services
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .OrderByDescending(static service => (int)service.Confidence)
            .Take(3)
            .Select(static service => Humanize(service.Kind.ToString()) + ": " + HumanizeEvidenceSource(service.EvidenceSource))
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Detected services",
            ValueLabel = info.DetectedServiceCount.ToString(),
            Summary = "DD scores visible Microsoft 365 workloads from identity, DNS, mail, and namespace signals rather than from a single banner or TXT record.",
            Tags = new[]
            {
                "Strong: " + info.StrongServiceCount,
                "Moderate: " + info.ModerateServiceCount,
                "Weak: " + info.WeakServiceCount
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildApplicationSnapshotCard(Microsoft365OverviewInfo info)
    {
        var samples = info.Tenant.DetectedDnsApplications
            .OrderByDescending(static item => (int)item.Confidence)
            .Take(3)
            .Select(static item => item.Name + ": " + item.EvidenceKind)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "DNS app footprint",
            ValueLabel = info.DetectedApplicationCount.ToString(),
            Summary = "Application and provider clues come from DD’s DNS fingerprinting pass across TXT, MX, NS, CNAME, and hostname evidence.",
            Tags = new[]
            {
                "Known subdomains: " + info.KnownSubdomainCount,
                "App categories: " + info.Tenant.DetectedDnsApplications.Select(static item => item.Category).Distinct().Count()
            },
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildAcceptedDomainSnapshotCard(Microsoft365OverviewInfo info)
    {
        var failingCount = info.MailDnsChecks.Count(static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning);
        var samples = info.Tenant.TenantDomains
            .OrderBy(static item => item.Role)
            .Take(3)
            .Select(static item => item.Domain + " (" + Humanize(item.Role.ToString()) + ")")
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Accepted domains",
            ValueLabel = info.AcceptedDomainCount.ToString(),
            Summary = "DD combines accepted-domain evidence with current mail control findings so the domain inventory is read together with the posture around it.",
            Tags = new[]
            {
                "Warnings: " + info.WarningCount,
                "Errors: " + info.ErrorCount,
                "Flagged controls: " + failingCount
            },
            Samples = samples
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildHighlightCards(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>
        {
            BuildIdentityNotesCard(info),
            BuildWorkloadNotesCard(info),
            BuildDomainFootprintCard(info)
        };

        return cards.Where(static card => card.Tags.Count > 0 || card.Samples.Count > 0).ToArray();
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildMailCards(Microsoft365OverviewInfo? info)
    {
        if (info == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        var cards = new List<DomainOverviewDetailCardView>();
        if (info.Spf != null)
        {
            cards.Add(BuildSpfCard(info.Spf));
        }

        if (info.Dkim.Count > 0)
        {
            cards.Add(BuildDkimCard(info.Dkim));
        }

        if (info.Dmarc != null)
        {
            cards.Add(BuildDmarcCard(info.Dmarc));
        }

        if (info.Mx != null)
        {
            cards.Add(BuildMxCard(info.Mx));
        }

        cards.Add(BuildTransportCard(info));
        cards.Add(BuildDnsInfrastructureCard(info));
        return cards;
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildServiceCoverageCards(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[]
        {
            BuildWorkloadCoverageCard(info),
            BuildMissingWorkloadCard(info.Tenant.Services)
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildDomainCoverageCards(Microsoft365OverviewInfo? info)
    {
        if (info?.Tenant == null)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return new[]
        {
            BuildTenantDomainCoverageCard(info.Tenant.TenantDomains),
            BuildKnownSubdomainCoverageCard(info.Tenant.KnownSubdomains)
        };
    }

    public static IReadOnlyList<DomainOverviewDetailCardView> BuildEvidenceSummaryCards(IReadOnlyList<Microsoft365EvidenceCategoryView>? groups)
    {
        if (groups == null || groups.Count == 0)
        {
            return Array.Empty<DomainOverviewDetailCardView>();
        }

        return groups
            .Take(3)
            .Select(BuildEvidenceSummaryCard)
            .ToArray();
    }

    public static IReadOnlyList<DetectedServiceView> BuildServices(IReadOnlyList<Microsoft365ServiceDetection>? services)
    {
        if (services == null || services.Count == 0)
        {
            return Array.Empty<DetectedServiceView>();
        }

        return services
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .OrderByDescending(static service => (int)service.Confidence)
            .ThenBy(static service => Humanize(service.Kind.ToString()), StringComparer.OrdinalIgnoreCase)
            .Select(static service => new DetectedServiceView
            {
                Name = Humanize(service.Kind.ToString()),
                ConfidenceLabel = FormatConfidence(service.Confidence),
                EvidenceSourceLabel = HumanizeEvidenceSource(service.EvidenceSource),
                ObservationCount = service.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value)),
                Summary = BuildServiceSummary(service),
                Samples = service.Evidence
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .Select(static value => Truncate(value.Trim(), 88))
                    .ToArray()
            })
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildTenantIdentityCard(Microsoft365TenantInfo tenant)
    {
        var tags = new List<string>
        {
            "Confidence: " + FormatConfidence(tenant.DetectionConfidence),
            "Cloud: " + Humanize(tenant.CloudInstance.ToString()),
            "Region: " + Humanize(tenant.Region.ToString())
        };

        tags.Add(tenant.ConsumerDomain ? "Consumer-linked" : "Managed tenant");

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenant.TenantName))
        {
            samples.Add("Tenant name: " + tenant.TenantName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.CompanyName))
        {
            samples.Add("Company: " + tenant.CompanyName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantId))
        {
            samples.Add("Tenant ID: " + tenant.TenantId);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantNamespaceDomain))
        {
            samples.Add("Namespace domain: " + tenant.TenantNamespaceDomain);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Tenant identity",
            ValueLabel = tenant.IsMicrosoft365Tenant ? "Microsoft 365 detected" : "Tenant not confirmed",
            Summary = "DD combined tenant namespace, cloud placement, and public Microsoft identity signals to establish the tenant identity footprint.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildWorkloadCoverageCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var totalModeled = tenant.Services.Count;
        var samples = new List<string>();
        samples.AddRange(tenant.WorkloadSummary.StrongServices.Take(3).Select(static value => "Strong: " + Humanize(value.ToString())));
        samples.AddRange(tenant.WorkloadSummary.ModerateServices.Take(2).Select(static value => "Moderate: " + Humanize(value.ToString())));

        return new DomainOverviewDetailCardView
        {
            Title = "Workload coverage",
            ValueLabel = info.DetectedServiceCount + "/" + totalModeled + " detected",
            Summary = "DD correlated identity, mail, DNS application, and known-subdomain signals to estimate how much of the Microsoft 365 workload surface is publicly visible.",
            Tags = new[]
            {
                "Strong: " + info.StrongServiceCount,
                "Moderate: " + info.ModerateServiceCount,
                "Weak: " + info.WeakServiceCount
            },
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildMissingWorkloadCard(IReadOnlyList<Microsoft365ServiceDetection> services)
    {
        var missing = services
            .Where(static service => service.Status != Microsoft365DetectionStatus.Detected)
            .Select(static service => Humanize(service.Kind.ToString()))
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "Workloads not observed",
            ValueLabel = missing.Length == 0 ? "All observed" : missing.Length + " not observed",
            Summary = missing.Length == 0
                ? "All modeled Microsoft 365 service families produced public DD evidence in this run."
                : "These modeled service families did not produce enough public DD evidence to be marked as detected in this run.",
            Tags = new[]
            {
                "Modeled families: " + services.Count,
                "Detected: " + services.Count(static service => service.Status == Microsoft365DetectionStatus.Detected)
            },
            Samples = missing.Take(6).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildAuthenticationPostureCard(Microsoft365TenantInfo tenant)
    {
        var tags = new List<string>
        {
            "Auth path: " + Humanize(tenant.AuthenticationPath.ToString()),
            "Enumeration: " + Humanize(tenant.UserEnumerationStatus.ToString()),
            "Throttling: " + Humanize(tenant.ThrottlingStatus.ToString())
        };

        if (tenant.IdentityProviderKind != TenantIdentityProviderKind.Unknown)
        {
            tags.Add("IdP: " + Humanize(tenant.IdentityProviderKind.ToString()));
        }

        if (tenant.FederationMode != Microsoft365FederationMode.Unknown)
        {
            tags.Add("Federation: " + Humanize(tenant.FederationMode.ToString()));
        }

        if (tenant.SmartLockoutStatus != Microsoft365AuthExposureStatus.Unknown)
        {
            tags.Add("Smart lockout: " + Humanize(tenant.SmartLockoutStatus.ToString()));
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenant.IdentityProvider))
        {
            samples.Add("Identity provider: " + tenant.IdentityProvider);
        }

        if (!string.IsNullOrWhiteSpace(tenant.AuthenticationProbeAddress))
        {
            samples.Add("Probe target: " + tenant.AuthenticationProbeAddress);
        }

        if (!string.IsNullOrWhiteSpace(tenant.NameSpaceType))
        {
            samples.Add("Namespace type: " + tenant.NameSpaceType);
        }

        samples.Add("Authentication probe " + (tenant.AuthenticationProbeSucceeded ? "succeeded." : "did not return a successful probe response."));

        return new DomainOverviewDetailCardView
        {
            Title = "Authentication posture",
            ValueLabel = FormatValue(tenant.IdentityProvider, Humanize(tenant.IdentityProviderKind.ToString())),
            Summary = "DD used Microsoft authentication probes and federation behavior to describe the tenant sign-in surface and external auth exposure.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildTenantDomainCoverageCard(IReadOnlyList<Microsoft365TenantDomain> domains)
    {
        var primaryCount = domains.Count(static item => item.Role == Microsoft365TenantDomainRole.Primary);
        var identityCount = domains.Count(static item => item.Role == Microsoft365TenantDomainRole.IdentityDomain);
        var acceptedCount = domains.Count(static item => item.Role == Microsoft365TenantDomainRole.AcceptedCustomDomain);
        var namespaceCount = domains.Count(static item => item.Role == Microsoft365TenantDomainRole.MicrosoftManagedNamespace);

        return new DomainOverviewDetailCardView
        {
            Title = "Tenant domain coverage",
            ValueLabel = domains.Count + " linked domain(s)",
            Summary = "DD grouped primary, accepted, identity-linked, and Microsoft-managed namespaces to map the tenant's public domain footprint.",
            Tags = new[]
            {
                "Primary: " + primaryCount,
                "Accepted: " + acceptedCount,
                "Identity-linked: " + identityCount,
                "Managed namespace: " + namespaceCount
            },
            Samples = domains
                .OrderBy(static item => item.Role)
                .Take(5)
                .Select(static item => item.Domain + " (" + Humanize(item.Role.ToString()) + ")")
                .ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildKnownSubdomainCoverageCard(IReadOnlyList<KnownMicrosoft365Subdomain> subdomains)
    {
        var resolving = subdomains.Count(static item => item.ResolutionStatus == SubdomainResolutionStatus.Resolves);
        var unresolved = subdomains.Count(static item => item.ResolutionStatus == SubdomainResolutionStatus.DoesNotResolve);
        var distinctRoles = subdomains.Select(static item => item.Role).Distinct().Count();

        return new DomainOverviewDetailCardView
        {
            Title = "Known subdomain coverage",
            ValueLabel = subdomains.Count + " subdomain(s)",
            Summary = "DD tracked known Microsoft-related naming patterns and current resolution status to outline the tenant's public Microsoft 365 hostname surface.",
            Tags = new[]
            {
                "Resolving: " + resolving,
                "Unresolved: " + unresolved,
                "Roles: " + distinctRoles
            },
            Samples = subdomains
                .OrderBy(static item => item.Role)
                .Take(5)
                .Select(static item => item.Name + " (" + Humanize(item.Role.ToString()) + ")")
            .ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildEvidenceSummaryCard(Microsoft365EvidenceCategoryView group)
    {
        var topLabels = group.Items
            .Take(3)
            .Select(static item => item.Label)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .ToArray();

        var totalSignals = group.Items.Sum(static item => item.ObservationCount);
        return new DomainOverviewDetailCardView
        {
            Title = group.CategoryLabel + " evidence",
            ValueLabel = group.ItemCount + " item(s)",
            Summary = "This evidence category contributed DD reasoning for the Microsoft 365 inference and is grouped here to show the strongest supporting signals first.",
            Tags = new[]
            {
                "Highest confidence: " + group.HighestConfidenceLabel,
                "Observed signals: " + totalSignals
            },
            Samples = topLabels
        };
    }

    private static DomainOverviewDetailCardView BuildProtocolSurfaceCard(Microsoft365TenantInfo tenant)
    {
        var tags = new List<string>
        {
            "Grant types: " + tenant.SupportedGrantTypes.Count,
            "Response types: " + tenant.SupportedResponseTypes.Count,
            "Evidence groups: " + tenant.EvidenceSummary.CategoryCount
        };

        if (tenant.EvidenceSummary.TotalCount > 0)
        {
            tags.Add("Evidence items: " + tenant.EvidenceSummary.TotalCount);
        }

        var samples = new List<string>();
        if (tenant.SupportedGrantTypes.Count > 0)
        {
            samples.Add("Grant types: " + string.Join(", ", tenant.SupportedGrantTypes.Take(4)));
        }

        if (tenant.SupportedResponseTypes.Count > 0)
        {
            samples.Add("Response types: " + string.Join(", ", tenant.SupportedResponseTypes.Take(4)));
        }

        samples.AddRange(tenant.EvidenceLedger
            .OrderByDescending(static item => (int)item.Confidence)
            .Take(2)
            .Select(static item => item.Label + ": " + BuildEvidenceSummary(item)));

        return new DomainOverviewDetailCardView
        {
            Title = "Protocol and evidence surface",
            ValueLabel = tenant.EvidenceSummary.CategoryCount + " evidence group(s)",
            Summary = "DD tracked the tenant's advertised OAuth surface and highest-confidence evidence groups to explain how the Microsoft 365 inference was built.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildSpfCard(SpfRecordInfo info)
    {
        var tags = new List<string>
        {
            info.SpfRecordExists ? "Published" : "Missing",
            info.AllMechanism ?? "No all policy",
            info.DnsLookupsCount + "/10 lookups"
        };

        if (info.HasRedirect)
        {
            tags.Add("Redirect");
        }

        if (info.HasExp)
        {
            tags.Add("exp=");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.SpfRecord))
        {
            samples.Add(Truncate(info.SpfRecord, 120));
        }

        samples.AddRange(info.Highlights.Take(2));
        if (samples.Count < 3)
        {
            samples.AddRange(info.ResolvedIncludeRecords.Take(2).Select(static value => "Include: " + value));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "SPF policy",
            ValueLabel = info.SpfRecordExists ? (info.AllMechanism ?? "Published") : "Missing",
            Summary = "DD evaluated SPF structure, lookup budget, include chain, and flattening posture for the tenant domain.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDkimCard(IReadOnlyList<DkimRecordInfo> selectors)
    {
        var validSelectors = selectors.Count(static item => item.ValidPublicKey && !item.WeakKey);
        var tags = new List<string>
        {
            validSelectors + "/" + selectors.Count + " valid"
        };

        if (selectors.Any(static item => item.WeakKey))
        {
            tags.Add("Weak key present");
        }

        if (selectors.Any(static item => item.OldKey))
        {
            tags.Add("Old key");
        }

        var samples = selectors
            .OrderByDescending(static item => item.ValidPublicKey)
            .ThenByDescending(static item => item.KeyLength)
            .Take(4)
            .Select(static item => item.Selector + ": " + (item.PublicKeyExists ? item.KeyLength + " bit " + item.KeyType : "no key"))
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "DKIM selectors",
            ValueLabel = selectors.Count + " selector(s)",
            Summary = "DD checked discovered selectors for key presence, key strength, and selector record quality.",
            Tags = tags,
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildDmarcCard(DmarcRecordInfo info)
    {
        var tags = new List<string>
        {
            info.DmarcRecordExists ? "Published" : "Missing",
            string.IsNullOrWhiteSpace(info.Policy) ? "No p=" : "p=" + info.Policy,
            "rua " + (info.MailtoRua.Count + info.HttpRua.Count)
        };

        if (info.WeakPolicy)
        {
            tags.Add("Weak policy");
        }

        if (info.UnauthorizedExternalReportDomains.Count > 0)
        {
            tags.Add("Unauthorized rua");
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(info.DmarcRecord))
        {
            samples.Add(Truncate(info.DmarcRecord, 120));
        }

        samples.AddRange(info.Highlights.Take(2));
        samples.AddRange(info.MailtoRua.Take(2).Select(static value => "rua: " + value));

        return new DomainOverviewDetailCardView
        {
            Title = "DMARC policy",
            ValueLabel = info.DmarcRecordExists ? (string.IsNullOrWhiteSpace(info.Policy) ? "Published" : info.Policy.ToUpperInvariant()) : "Missing",
            Summary = "DD validated policy mode, alignment, and reporting destinations for the tenant DMARC record.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildMxCard(MxInfo info)
    {
        var tags = new List<string>
        {
            info.MxRecordExists ? info.MxRecords.Count + " record(s)" : "Missing",
            info.HasBackupServers ? "Backup MX" : "Single path",
            info.Ipv6Supported ? "IPv6" : "No IPv6"
        };

        if (!string.IsNullOrWhiteSpace(info.ProviderPrimary))
        {
            tags.Add(info.ProviderPrimary);
        }

        var samples = info.Hosts
            .Take(4)
            .Select(static host => (host.Priority.HasValue ? host.Priority.Value + " " : string.Empty) + host.Host)
            .ToArray();

        return new DomainOverviewDetailCardView
        {
            Title = "MX routing",
            ValueLabel = info.MxRecordExists ? info.MxRecords.Count + " route(s)" : "Missing",
            Summary = "DD analyzed tenant MX routing, provider fingerprints, redundancy, and target quality for the mail path.",
            Tags = tags,
            Samples = samples
        };
    }

    private static DomainOverviewDetailCardView BuildTransportCard(Microsoft365OverviewInfo info)
    {
        var tags = new List<string>();
        if (info.Mtasts != null)
        {
            tags.Add(info.Mtasts.PolicyPresent ? "MTA-STS" : "No MTA-STS");
        }

        if (info.TlsRpt != null)
        {
            tags.Add(info.TlsRpt.TlsRptRecordExists ? "TLS-RPT" : "No TLS-RPT");
        }

        if (info.Bimi != null)
        {
            tags.Add(info.Bimi.BimiRecordExists ? "BIMI" : "No BIMI");
        }

        if (info.Caa != null)
        {
            tags.Add(info.Caa.ValidRecords > 0 ? "CAA " + info.Caa.ValidRecords : "No CAA");
        }

        if (info.Dane != null)
        {
            tags.Add(info.Dane.NumberOfRecords > 0 ? "DANE " + info.Dane.ValidRecordCount : "No DANE");
        }

        var samples = new List<string>();
        if (info.Mtasts != null)
        {
            samples.Add("MTA-STS: " + info.Mtasts.Summary);
        }

        if (info.TlsRpt != null)
        {
            samples.Add("TLS-RPT: " + info.TlsRpt.Summary);
        }

        if (info.Bimi != null)
        {
            samples.Add("BIMI: " + info.Bimi.Summary);
        }

        if (info.Caa != null)
        {
            samples.Add("CAA: " + info.Caa.Summary);
        }

        if (info.Dane != null)
        {
            samples.Add("DANE: " + info.Dane.Summary);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Transport and trust policies",
            ValueLabel = tags.Count(static tag => !tag.StartsWith("No ", StringComparison.Ordinal)) + " enabled",
            Summary = "DD checked transport policy, reporting, brand indicators, certificate authority policy, and TLSA posture for tenant mail delivery hardening.",
            Tags = tags,
            Samples = samples.Take(5).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDnsInfrastructureCard(Microsoft365OverviewInfo info)
    {
        var tags = new List<string>();
        if (info.Dnssec != null)
        {
            tags.Add(info.Dnssec.ChainValid ? "DNSSEC valid" : "DNSSEC issues");
        }

        if (info.Ns != null)
        {
            tags.Add(info.Ns.NsRecords.Count + " NS");
            tags.Add(info.Ns.AsnDistinctCount + " ASN");
        }

        var samples = new List<string>();
        if (info.Ns != null)
        {
            samples.AddRange(info.Ns.NsRecords.Take(3).Select(static value => "NS: " + value));
        }

        if (info.Dnssec != null)
        {
            samples.Add("DNSSEC: chain " + (info.Dnssec.ChainValid ? "valid" : "invalid") + ", DS " + (info.Dnssec.DsMatch ? "match" : "review"));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "DNS infrastructure",
            ValueLabel = info.Ns != null ? info.Ns.NsRecords.Count + " nameserver(s)" : "Unknown",
            Summary = "DD checked authoritative nameservers, resolver diversity, and DNSSEC integrity for the tenant-facing domain.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Take(4).ToArray()
        };
    }

    public static IReadOnlyList<TenantDomainView> BuildTenantDomains(IReadOnlyList<Microsoft365TenantDomain>? domains)
    {
        if (domains == null || domains.Count == 0)
        {
            return Array.Empty<TenantDomainView>();
        }

        return domains
            .OrderBy(static item => item.Role)
            .ThenBy(static item => item.Domain, StringComparer.OrdinalIgnoreCase)
            .Select(static item => new TenantDomainView
            {
                Domain = item.Domain,
                RoleLabel = Humanize(item.Role.ToString()),
                ConfidenceLabel = FormatConfidence(item.Confidence),
                ObservationCount = item.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value)),
                Summary = BuildTenantDomainSummary(item),
                Samples = item.Evidence
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .Select(static value => Truncate(value.Trim(), 88))
                    .ToArray()
            })
            .ToArray();
    }

    private static DomainOverviewDetailCardView BuildIdentityNotesCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var tags = new List<string>
        {
            "Confidence: " + FormatConfidence(tenant.DetectionConfidence),
            "Auth path: " + Humanize(tenant.AuthenticationPath.ToString())
        };

        if (tenant.IdentityProviderKind != TenantIdentityProviderKind.Unknown)
        {
            tags.Add("IdP: " + Humanize(tenant.IdentityProviderKind.ToString()));
        }

        if (tenant.FederationMode != Microsoft365FederationMode.Unknown)
        {
            tags.Add("Federation: " + Humanize(tenant.FederationMode.ToString()));
        }

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(tenant.CompanyName))
        {
            samples.Add("Company: " + tenant.CompanyName);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantId))
        {
            samples.Add("Tenant ID: " + tenant.TenantId);
        }

        if (!string.IsNullOrWhiteSpace(tenant.IdentityProvider))
        {
            samples.Add("Identity provider: " + tenant.IdentityProvider);
        }

        if (!string.IsNullOrWhiteSpace(tenant.TenantNamespaceDomain))
        {
            samples.Add("Namespace domain: " + tenant.TenantNamespaceDomain);
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Identity notes",
            ValueLabel = tenant.IsMicrosoft365Tenant ? "Microsoft 365 detected" : "Tenant not confirmed",
            Summary = "DD combined tenant identifiers, authentication probe results, and federation posture to build the identity summary for this domain.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildWorkloadNotesCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var tags = new List<string>
        {
            "Detected: " + info.DetectedServiceCount,
            "Strong: " + info.StrongServiceCount,
            "Moderate: " + info.ModerateServiceCount
        };

        if (info.WeakServiceCount > 0)
        {
            tags.Add("Weak: " + info.WeakServiceCount);
        }

        var samples = new List<string>();
        samples.AddRange(tenant.Services
            .Where(static service => service.Status == Microsoft365DetectionStatus.Detected)
            .OrderByDescending(static service => (int)service.Confidence)
            .Take(4)
            .Select(static service => Humanize(service.Kind.ToString()) + ": " + Humanize(service.EvidenceSource.ToString())));

        if (samples.Count < 4)
        {
            samples.AddRange(info.Highlights
                .Where(static item => item.Contains("workload", StringComparison.OrdinalIgnoreCase) || item.Contains("service", StringComparison.OrdinalIgnoreCase))
                .Take(4 - samples.Count));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Workload notes",
            ValueLabel = info.DetectedServiceCount + " workload(s)",
            Summary = "DD correlated mail, identity, subdomain, and DNS-application signals to estimate the Microsoft 365 workload footprint.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray()
        };
    }

    private static DomainOverviewDetailCardView BuildDomainFootprintCard(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        var tags = new List<string>
        {
            "Accepted domains: " + info.AcceptedDomainCount,
            "Known subdomains: " + info.KnownSubdomainCount,
            "App hints: " + info.DetectedApplicationCount
        };

        if (tenant.DnsApplicationSummary.CategoryCount > 0)
        {
            tags.Add("App categories: " + tenant.DnsApplicationSummary.CategoryCount);
        }

        var samples = new List<string>();
        samples.AddRange(tenant.TenantDomains
            .OrderBy(static item => item.Role)
            .Take(3)
            .Select(static item => item.Domain + " (" + Humanize(item.Role.ToString()) + ")"));
        samples.AddRange(tenant.KnownSubdomains
            .OrderBy(static item => item.Role)
            .Take(2)
            .Select(static item => item.Name + " (" + Humanize(item.Role.ToString()) + ")"));

        if (samples.Count < 5)
        {
            samples.AddRange(info.Highlights
                .Where(static item => item.Contains("domain", StringComparison.OrdinalIgnoreCase) || item.Contains("App footprint", StringComparison.OrdinalIgnoreCase))
                .Take(5 - samples.Count));
        }

        return new DomainOverviewDetailCardView
        {
            Title = "Domain footprint notes",
            ValueLabel = (info.AcceptedDomainCount + info.KnownSubdomainCount) + " linked names",
            Summary = "DD used tenant-linked domains, known Microsoft subdomains, and DNS application signals to map the public tenant footprint.",
            Tags = tags,
            Samples = samples.Where(static item => !string.IsNullOrWhiteSpace(item)).Distinct(StringComparer.OrdinalIgnoreCase).Take(5).ToArray()
        };
    }

    public static IReadOnlyList<KnownSubdomainView> BuildKnownSubdomains(IReadOnlyList<KnownMicrosoft365Subdomain>? subdomains)
    {
        if (subdomains == null || subdomains.Count == 0)
        {
            return Array.Empty<KnownSubdomainView>();
        }

        return subdomains
            .OrderBy(static item => item.Role)
            .ThenBy(static item => item.Name, StringComparer.OrdinalIgnoreCase)
            .Select(static item => new KnownSubdomainView
            {
                Name = item.Name,
                RoleLabel = Humanize(item.Role.ToString()),
                ResolutionLabel = Humanize(item.ResolutionStatus.ToString()),
                ObservationCount = item.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value)),
                Summary = BuildKnownSubdomainSummary(item),
                Samples = item.Evidence
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(3)
                    .Select(static value => Truncate(value.Trim(), 88))
                    .ToArray()
            })
            .ToArray();
    }

    public static IReadOnlyList<Microsoft365EvidenceCategoryView> BuildEvidenceCategories(IReadOnlyList<Microsoft365EvidenceItem>? evidenceItems)
    {
        if (evidenceItems == null || evidenceItems.Count == 0)
        {
            return Array.Empty<Microsoft365EvidenceCategoryView>();
        }

        return evidenceItems
            .Where(static item => item.Confidence != Microsoft365DetectionConfidence.Unknown)
            .GroupBy(static item => item.Category)
            .OrderByDescending(static group => group.Max(static item => (int)item.Confidence))
            .ThenBy(static group => Humanize(group.Key.ToString()), StringComparer.OrdinalIgnoreCase)
            .Select(static group => new Microsoft365EvidenceCategoryView
            {
                CategoryLabel = Humanize(group.Key.ToString()),
                ItemCount = group.Count(),
                HighestConfidenceLabel = FormatConfidence(group.Max(static item => item.Confidence)),
                Items = group
                    .OrderByDescending(static item => (int)item.Confidence)
                    .ThenBy(static item => item.Label, StringComparer.OrdinalIgnoreCase)
                    .Select(static item => new Microsoft365EvidenceItemView
                    {
                        Label = item.Label,
                        ConfidenceLabel = FormatConfidence(item.Confidence),
                        ObservationCount = item.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value)),
                        Summary = BuildEvidenceSummary(item),
                        Samples = item.Evidence
                            .Where(static value => !string.IsNullOrWhiteSpace(value))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .Take(3)
                            .Select(static value => Truncate(value.Trim(), 96))
                            .ToArray()
                    })
                    .ToArray()
            })
            .ToArray();
    }

    private static string BuildServiceSummary(Microsoft365ServiceDetection service)
    {
        var source = HumanizeEvidenceSource(service.EvidenceSource);
        var observationCount = service.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value));
        var observationLabel = observationCount == 1 ? "1 signal" : observationCount + " signals";

        if (service.TenantContextBoosted)
        {
            return $"{source} confirmed with tenant-correlated evidence across {observationLabel}.";
        }

        return $"{source} confirmed from public Microsoft 365 signals across {observationLabel}.";
    }

    private static string BuildEvidenceSummary(Microsoft365EvidenceItem item)
    {
        var category = item.Category switch
        {
            Microsoft365EvidenceCategory.Identity => "Identity endpoints and tenant identifiers support this inference.",
            Microsoft365EvidenceCategory.Mail => "Mail routing and policy records support this inference.",
            Microsoft365EvidenceCategory.Service => "Workload-specific public signals support this inference.",
            Microsoft365EvidenceCategory.DnsApplication => "Third-party DNS application signals support this inference.",
            Microsoft365EvidenceCategory.Authentication => "Authentication probe behavior supports this inference.",
            Microsoft365EvidenceCategory.Domain => "Tenant-domain relationships support this inference.",
            _ => Humanize(item.Category.ToString()) + " evidence supports this inference."
        };

        var observationCount = item.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (observationCount <= 0)
        {
            return category;
        }

        return category + " Observed in " + observationCount + " signal(s).";
    }

    private static string BuildTenantDomainSummary(Microsoft365TenantDomain domain)
    {
        var roleText = domain.Role switch
        {
            Microsoft365TenantDomainRole.Primary => "Primary tenant domain confirmed from public Microsoft identity and namespace signals.",
            Microsoft365TenantDomainRole.IdentityDomain => "Identity-linked domain inferred from Microsoft authentication and tenant metadata.",
            Microsoft365TenantDomainRole.AcceptedCustomDomain => "Accepted custom domain inferred from tenant-linked mail and DNS evidence.",
            Microsoft365TenantDomainRole.MicrosoftManagedNamespace => "Microsoft-managed namespace tied to the tenant footprint.",
            _ => "Tenant-related domain discovered from DD public-signal evidence."
        };

        var observationCount = domain.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (observationCount <= 0)
        {
            return roleText;
        }

        return roleText + " Observed in " + observationCount + " signal(s).";
    }

    private static string BuildKnownSubdomainSummary(KnownMicrosoft365Subdomain subdomain)
    {
        var summary = Humanize(subdomain.Role.ToString()) + " subdomain with " + Humanize(subdomain.ResolutionStatus.ToString()).ToLowerInvariant() + " resolution status.";
        var observationCount = subdomain.Evidence.Count(static value => !string.IsNullOrWhiteSpace(value));
        if (observationCount <= 0)
        {
            return summary;
        }

        return summary + " Observed in " + observationCount + " signal(s).";
    }

    private static string HumanizeEvidenceSource(Microsoft365ServiceEvidenceSourceKind evidenceSource)
    {
        return evidenceSource switch
        {
            Microsoft365ServiceEvidenceSourceKind.IdentityProbe => "Identity probe evidence",
            Microsoft365ServiceEvidenceSourceKind.MailProtocol => "Mail protocol evidence",
            Microsoft365ServiceEvidenceSourceKind.KnownSubdomain => "Known subdomain evidence",
            Microsoft365ServiceEvidenceSourceKind.DnsApplication => "Application footprint evidence",
            _ => "Public signal evidence"
        };
    }

    private static string FormatValue(string? value, string fallback)
    {
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static string FormatConfidence(Microsoft365DetectionConfidence confidence)
    {
        return confidence == Microsoft365DetectionConfidence.Unknown
            ? "Observed"
            : Humanize(confidence.ToString());
    }

    private static string FormatIdentityPostureLabel(Microsoft365OverviewInfo info)
    {
        var tenant = info.Tenant;
        if (info.IsBrowserLimited && tenant.AuthenticationPath == Microsoft365AuthPathKind.Unknown && tenant.IdentityProviderKind == TenantIdentityProviderKind.Unknown)
        {
            return "Auth not probed";
        }

        if (tenant.FederationMode == Microsoft365FederationMode.CloudManaged)
        {
            return tenant.UserEnumerationStatus == Microsoft365AuthExposureStatus.Exposed ? "Cloud-managed, exposed realm" : "Cloud-managed";
        }

        if (tenant.FederationMode == Microsoft365FederationMode.Federated)
        {
            return "Federated identity";
        }

        return tenant.AuthenticationPath != Microsoft365AuthPathKind.Unknown
            ? Humanize(tenant.AuthenticationPath.ToString())
            : "Identity observed";
    }

    private static string Humanize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(value.Length + 8);
        builder.Append(value[0]);

        for (var i = 1; i < value.Length; i++)
        {
            var current = value[i];
            var previous = value[i - 1];
            if (char.IsUpper(current) && (char.IsLower(previous) || char.IsDigit(previous)))
            {
                builder.Append(' ');
            }
            else if (char.IsDigit(current) && char.IsLetter(previous) && !char.IsDigit(previous))
            {
                builder.Append(' ');
            }

            builder.Append(current);
        }

        return builder.ToString();
    }

    private static string Truncate(string value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
        {
            return value;
        }

        return value.Substring(0, maxLength - 1) + "…";
    }
}

internal sealed class DetectedServiceView
{
    public string Name { get; init; } = string.Empty;
    public string ConfidenceLabel { get; init; } = string.Empty;
    public string EvidenceSourceLabel { get; init; } = string.Empty;
    public int ObservationCount { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}

internal sealed class TenantDomainView
{
    public string Domain { get; init; } = string.Empty;
    public string RoleLabel { get; init; } = string.Empty;
    public string ConfidenceLabel { get; init; } = string.Empty;
    public int ObservationCount { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}

internal sealed class KnownSubdomainView
{
    public string Name { get; init; } = string.Empty;
    public string RoleLabel { get; init; } = string.Empty;
    public string ResolutionLabel { get; init; } = string.Empty;
    public int ObservationCount { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}

internal sealed class Microsoft365EvidenceCategoryView
{
    public string CategoryLabel { get; init; } = string.Empty;
    public int ItemCount { get; init; }
    public string HighestConfidenceLabel { get; init; } = string.Empty;
    public IReadOnlyList<Microsoft365EvidenceItemView> Items { get; init; } = Array.Empty<Microsoft365EvidenceItemView>();
}

internal sealed class Microsoft365EvidenceItemView
{
    public string Label { get; init; } = string.Empty;
    public string ConfidenceLabel { get; init; } = string.Empty;
    public int ObservationCount { get; init; }
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
}
