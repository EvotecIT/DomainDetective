using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides proofpoint essentials provider functionality.</summary>
public sealed class ProofpointEssentialsProvider : IMailProvider {
    /// <summary>Represents the id value.</summary>
    public string Id => "proofpoint-essentials";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "Proofpoint Essentials";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.Gateway | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new[]
    {
        "*.ppe-hosted.com",
        "ppe-hosted.com"
    };

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        // Proofpoint Essentials publishes SPF guidance that typically references ppe-hosted.com includes
        "ppe-hosted.com"
    };

    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new[] { "pp", "proofpoint" };
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "pphosted.com", "proofpoint.com" };

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
        Arc = new ProviderDocLink { Url = null, Title = "ARC", Summary = "No Essentials ARC signing page.", Notes = "Gateway evaluates SPF/DKIM/DMARC; confirm pass-through behavior in policies.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://www.proofpoint.com/us/blog/email-and-cloud-threats/how-use-brand-logos-email-using-bimi", Title = "How to use brand logos in email using BIMI", Summary = "BIMI overview and prerequisites from Proofpoint.", Notes = "BIMI configured via DNS/VMC; display handled by receivers (Gmail/Apple/Yahoo).", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/How_does_DMARC_work_with_Proofpoint_Essentials%3F", Title = "How DMARC works with Proofpoint Essentials", Summary = "Explains DMARC evaluation behavior on inbound mail.", Notes = "Essentials doesn’t bounce solely on DMARC policy; actions vary by configuration.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/000_gettingstarted/020_connectiondetails", Title = "Connection details (SPF)", Summary = "Region-specific SPF include tokens (_spf-us/_spf-eu.ppe-hosted.com).", Notes = "Use correct region include; keep total SPF lookups ≤ 10.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Administrator_Topics/030_domains/Configuring_Outbound_DKIM_Signing", Title = "Configuring outbound DKIM signing", Summary = "Create keys, publish DNS, enable signing per domain.", Notes = "Rotate keys and verify DNS propagation before enforcement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No Essentials-specific MTA-STS admin doc.", Notes = "Implement at your domain; pair with TLS-RPT first.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No Essentials-specific TLS-RPT page.", Notes = "Add _smtp._tls TXT; use external tooling for report parsing.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://help.proofpoint.com/Proofpoint_Essentials/Email_Security/Support/Proofpoint_Essentials_Support_Guide", Title = "Proofpoint Essentials Support Guide", Summary = "Central admin references that impact deliverability.", Notes = "See anti-spoofing policies and connection details linked within.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
