using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides barracuda email gateway defense provider functionality.</summary>
public sealed class BarracudaEmailGatewayDefenseProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "barracuda-egd";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Barracuda Email Gateway Defense";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "ess*.barracudanetworks.com",
        "*.barracudanetworks.com"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        // Pattern varies by region; match base to raise confidence without overfitting
        "spf.ess",
        "barracudanetworks.com"
    };

    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new string[0];
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "barracudanetworks.com" };

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
        Arc = new ProviderDocLink { Url = null, Title = "ARC", Summary = "No specific ARC feature doc located.", Notes = "Gateway verifies SPF/DKIM/DMARC; ARC pass-through depends on policies/version.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = null, Title = "BIMI", Summary = "Gateway doesn’t control BIMI display.", Notes = "Ensure headers preserved; BIMI is sender DNS + receiver feature.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://campus.barracuda.com/product/emailsecuritygateway/doc/171806726/dmarc-verification/", Title = "DMARC verification", Summary = "DMARC verification behavior for ESG/CPL.", Notes = "Feature available via Cloud Protection Layer; may require support enablement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://campus.barracuda.com/product/emailgatewaydefense/doc/96023038/sender-policy-framework-for-outbound-mail/", Title = "SPF for outbound mail (regional includes)", Summary = "Region-specific SPF include tokens for EGD.", Notes = "Select correct region include (US/EU/UK/DE/CA/AU/IN); keep lookups ≤ 10.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://campus.barracuda.com/product/emailsecuritygateway/doc/3866643/sender-authentication/", Title = "Sender authentication (DKIM handling)", Summary = "How Barracuda evaluates DKIM on inbound mail.", Notes = "Outbound DKIM features vary by product/plan; verify in current UI/docs.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No Barracuda-specific MTA-STS admin doc.", Notes = "Implement at your domain; pair with TLS-RPT before enforce.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No Barracuda-specific TLS-RPT page.", Notes = "Publish _smtp._tls TXT; parse reports with tooling.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://assets.barracuda.com/assets/docs/dms/ebook-dmarc-us.pdf", Title = "DMARC — understanding and adoption", Summary = "Barracuda program guidance for DMARC adoption.", Notes = "Covers policy rollout and reporting to improve deliverability and reduce spoofing.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
