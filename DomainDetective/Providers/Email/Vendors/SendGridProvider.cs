using System.Collections.Generic;

namespace DomainDetective.Providers.Email.Vendors;

/// <summary>Provides send grid provider functionality.</summary>
public sealed class SendGridProvider : IMailProvider
{
    /// <summary>Represents the id value.</summary>
    public string Id => "sendgrid";
    /// <summary>Represents the display name value.</summary>
    public string DisplayName => "SendGrid";
    /// <summary>Represents the capabilities value.</summary>
    public ProviderCapability Capabilities => ProviderCapability.OutboundOnly | ProviderCapability.DkimSigning | ProviderCapability.SpfPublish;

    /// <summary>Represents the mx host patterns value.</summary>
    public IEnumerable<string> MxHostPatterns => new string[0];

    /// <summary>Represents the spf required tokens value.</summary>
    public IEnumerable<string> SpfRequiredTokens => new[]
    {
        "include:sendgrid.net"
    };

    /// <summary>Represents the dkim selector hints value.</summary>
    public IEnumerable<string> DkimSelectorHints => new[] { "s1", "s2" };
    /// <summary>Represents the dkim cname suffixes value.</summary>
    public IEnumerable<string> DkimCnameSuffixes => new[] { "sendgrid.net" };

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
        Arc = new ProviderDocLink { Url = null, Title = "ARC with SendGrid", Summary = "No outbound ARC signing; ARC is for intermediaries/forwarders.", Notes = "Ensure DKIM alignment and correct SPF (include sendgrid.net via Domain Auth).", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Bimi = new ProviderDocLink { Url = "https://support.sendgrid.com/hc/en-us/articles/15263626617371-Overview-of-BIMI-and-SendGrid", Title = "Overview of BIMI and SendGrid", Summary = "Explains BIMI prerequisites and where SendGrid fits.", Notes = "Configure BIMI via DNS/VMC; not inside SendGrid UI. See also Twilio blog walkthrough.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dmarc = new ProviderDocLink { Url = "https://www.twilio.com/docs/sendgrid/ui/sending-email/how-to-implement-dmarc", Title = "How to implement DMARC", Summary = "DMARC overview and implementation steps for SendGrid senders.", Notes = "Authenticate domain first; monitor DMARC reports prior to enforcement.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Spf   = new ProviderDocLink { Url = "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/spf-records", Title = "SPF records explained", Summary = "SPF concepts and SendGrid guidance.", Notes = "Automated Security may create a unique SPF for your branded subdomain/return-path.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        Dkim  = new ProviderDocLink { Url = "https://support.sendgrid.com/hc/en-us/articles/4408024201627-Use-a-Custom-DKIM-Selector-for-Authentication", Title = "Use a custom DKIM selector", Summary = "Selector options and domain authentication process.", Notes = "Default s1/s2; rotate keys; ensure only final sender signs to avoid breaks in transit.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) },
        MtaSts = new ProviderDocLink { Url = null, Title = "MTA-STS", Summary = "No SendGrid-specific MTA-STS doc.", Notes = "Implement MTA-STS at your receiving domain; independent of SendGrid.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        TlsRpt = new ProviderDocLink { Url = null, Title = "TLS-RPT", Summary = "No SendGrid-specific TLS-RPT doc.", Notes = "Publish _smtp._tls TXT; parse reports with your tooling.", IsPublic = true, IsThirdParty = true, LastVerified = new System.DateTime(2025, 9, 9) },
        Deliverability = new ProviderDocLink { Url = "https://support.sendgrid.com/hc/en-us/articles/17404397687323-Twilio-SendGrid-Support-Deliverability-Guide", Title = "Deliverability guide", Summary = "Consolidated deliverability best practices for SendGrid.", Notes = "See also Twilio blog on BIMI setup for step-by-step examples.", IsPublic = true, IsThirdParty = false, LastVerified = new System.DateTime(2025, 9, 9) }
    };
}
