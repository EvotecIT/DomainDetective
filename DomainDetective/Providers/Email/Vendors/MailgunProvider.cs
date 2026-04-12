using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides mailgun provider functionality.</summary>
public sealed class MailgunProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "mailgun";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Mailgun";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new string[0];

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new[] { "include:mailgun.org" };
    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new[] { "krs", "mg" };
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "mailgun.org" };

    /// <summary>Represents the single mx ok value.</summary>
    public bool SingleMxOk => false;
    /// <summary>Represents the recommended min mx records value.</summary>
    public int RecommendedMinMxRecords => 0;
    /// <summary>Represents the minimum dkim selectors to pass value.</summary>
    public int MinimumDkimSelectorsToPass => 0;
    /// <summary>Represents the subdomain policy recommendation value.</summary>
    public DmarcSubdomainPolicyRecommendation SubdomainPolicyRecommendation => DmarcSubdomainPolicyRecommendation.MatchParent;
    // Documentation (source of truth)

    /// <summary>Represents the docs value.</summary>
    public ProviderDocumentation Docs => new ProviderDocumentation {
        Provider = DisplayName,
        Arc = new ProviderDocLink { Url = "https://www.mailgun.com/blog/deliverability/authentication-received-chain/", Title = "Understand ARC and why you need it", Summary = "Mailgun adds ARC headers to inbound/forwarded messages.", Notes = "Automatic for Routes/mailing lists; outbound ARC not applicable; see release note as well.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://help.mailgun.com/hc/en-us/articles/4402603267739-BIMI-Brand-Indicators-Avatars-Logos-Profile-Images", Title = "BIMI (brand indicators) with Mailgun", Summary = "Explains BIMI and DNS-side configuration.", Notes = "Requires DMARC enforcement; VMC typically required by major receivers.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://help.mailgun.com/hc/en-us/articles/13285772266011-DMARC", Title = "DMARC", Summary = "DMARC primer and monitoring options for Mailgun users.", Notes = "Red Sift/DMARC analyzer integrations available for reporting.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://www.mailgun.com/blog/deliverability/spf-records-basics/", Title = "SPF records basics", Summary = "SPF publishing overview referencing Mailgun control panel values.", Notes = "Use the UI-provided include/ip4 mechanisms for your sending domain(s).", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://www.mailgun.com/blog/deliverability/understanding-dkim-how-it-works/", Title = "Understanding DKIM", Summary = "DKIM concepts and Mailgun selector/key length notes.", Notes = "2048-bit keys recommended; split long TXT values if DNS length limits apply.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No Mailgun-specific MTA-STS doc.", Notes = "Implement at your domain; independent of Mailgun.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No Mailgun-specific TLS-RPT doc.", Notes = "Publish _smtp._tls TXT; parse reports with tooling.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://www.mailgun.com/blog/deliverability/email-authentication-your-id-card-sending/", Title = "Email authentication & deliverability", Summary = "Auth and modern sender requirements across inbox providers.", Notes = "Emphasizes SPF/DKIM/DMARC and BIMI for bulk-sender compliance.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
