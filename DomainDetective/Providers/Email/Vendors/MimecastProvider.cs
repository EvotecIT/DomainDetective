using System;
using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides mimecast provider functionality.</summary>
public sealed class MimecastProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "mimecast";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Mimecast";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.mimecast.com",
        "inbound*.mimecast.com",
        "mx*.mimecast.com",
        "us-smtp-inbound-*.mimecast.com"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => Array.Empty<string>();

    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => Array.Empty<string>();
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mimecast.com" };

    /// <summary>Represents the single mx ok value.</summary>
    public bool SingleMxOk => false;
    /// <summary>Represents the recommended min mx records value.</summary>
    public int RecommendedMinMxRecords => 2;
    /// <summary>Represents the minimum dkim selectors to pass value.</summary>
    public int MinimumDkimSelectorsToPass => 0;
    /// <summary>Represents the subdomain policy recommendation value.</summary>
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    /// <summary>Represents the docs value.</summary>
    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000321250579-Email-Security-Cloud-Integrated-Trusted-ARC-Sealer-Mar-2024", Title = "Trusted ARC Sealer (Cloud Integrated)", Summary = "Configure Mimecast as a Trusted ARC Sealer in Microsoft 365.", Notes = "Ensures auth results survive processing; some integrations add ARC trust automatically.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000666276243-Email-Security-Cloud-Gateway-Brand-Indicators-Message-Identification", Title = "BIMI (Brand Indicators) guidance", Summary = "Gateway considerations for BIMI.", Notes = "Gateways don’t control display; ensure pass-through and sender DMARC/VMC compliance.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000616407315-DMARC-Analyzer-Policies", Title = "DMARC Analyzer — Policies", Summary = "Overview of DMARC policies via Mimecast DMARC Analyzer.", Notes = "Reporting/analytics for DMARC program rollout and enforcement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000792642963-Connect-Application-Implementing-SPF-for-Outbound-Email", Title = "Implementing SPF for Outbound", Summary = "Publish SPF includes for Mimecast outbound.", Notes = "Select correct region include; ensure total lookups ≤ 10.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000468841107-Policies-DNS-Authentication-Overview", Title = "DNS Authentication overview (DKIM)", Summary = "Guidance for DKIM signing when routing via Mimecast.", Notes = "Only the final sender should sign to avoid breaking DKIM after transit.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000414937491-Email-Security-Cloud-Gateway-Support-for-MTA-STS-Jun-2023", Title = "Support for MTA-STS", Summary = "Mimecast supports MTA-STS and TLS-RPT generation.", Notes = "Outbound respects recipient MTA-STS; monitor TLS-RPT before enforcing.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = "https://mimecastsupport.zendesk.com/hc/en-us/articles/34000414937491-Email-Security-Cloud-Gateway-Support-for-MTA-STS-Jun-2023", Title = "TLS-RPT support", Summary = "TLS-RPT reporting capabilities and considerations.", Notes = "Reports may be received even if the recipient isn’t a Mimecast customer.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://www.mimecast.com/products/dmarc-analyzer/", Title = "DMARC Analyzer", Summary = "DMARC analytics to improve deliverability and reduce spoofing.", Notes = "Use for program oversight and policy rollout.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
