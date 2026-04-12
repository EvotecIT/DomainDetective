using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides cisco secure email provider functionality.</summary>
public sealed class CiscoSecureEmailProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "cisco-secure-email";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Cisco Secure Email";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.iphmx.com",
        "*.secure.ironport.com",
        "*.emailsecurity.cisco.com",
        "*.esa.cisco.com"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new string[0];
    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new string[0];
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "emailsecurity.cisco.com", "ironport.com" };

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
        Arc = new ProviderDocLink { Url = null, Title = "ARC", Summary = "No dedicated ESA/SEG ARC signing feature doc surfaced.", Notes = "Use ESA SPF/DKIM/DMARC features; ARC usually handled by forwarders/receivers.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = null, Title = "BIMI", Summary = "Gateway doesn’t control BIMI display.", Notes = "Ensure headers pass-through; BIMI is sender DNS + receiver UI feature.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://www.cisco.com/site/us/en/learn/topics/security/what-is-dmarc.html", Title = "What is DMARC?", Summary = "Cisco’s DMARC overview and Domain Protection references.", Notes = "Use Cisco Domain Protection for reporting/ops at scale if needed.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/117973-faq-esa-00.html", Title = "SPF configuration and best practices (ESA)", Summary = "Inbound SPF checking scenarios and configuration.", Notes = "Covers exemptions and policies; adjust to your environment.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance/213939-esa-configure-dkim-signing.html", Title = "Configure DKIM signing on ESA", Summary = "Generate/publish keys and enable DKIM on ESA/CES.", Notes = "See also 'send on behalf of other domains' configuration guides.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = "https://www.cisco.com/c/en/us/support/docs/security/email-security-appliance-c690x/222782-configure-secure-email-gateway-outbound.html", Title = "Configure SEG outbound MTA-STS", Summary = "Outbound handling and configuration details.", Notes = "AsyncOS docs detail behavior/controls by version; verify for 16.x+.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No ESA-specific TLS-RPT receiver doc.", Notes = "Implement _smtp._tls TXT; use Cisco Domain Protection/third-party to parse.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://www.cisco.com/c/dam/en/us/td/docs/security/phishing_protection-and-domain_protection/dp_user_guide.pdf", Title = "Cisco Domain Protection — User Guide", Summary = "DMARC operations, reporting and rollout practices.", Notes = "Program governance guidance for complex estates and multiple brands.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
